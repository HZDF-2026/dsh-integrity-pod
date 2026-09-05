// bitwin.cpp — see bitwin.h. Mirrors plugins/dsh-integrity-bitwin/index.js.
#include "bitwin.h"

#include "jsjson.h"
#include "sha256.h"
#include "util.h"

#include <algorithm>
#include <cmath>
#include <map>
#include <stdexcept>
#include <vector>

namespace dship {

namespace {

const long long DEFAULT_TIMEOUT_MS = 120000;
const long long OUTPUT_CAP_BYTES = 10LL * 1024 * 1024;
const long long MAX_FILE_BYTES = 8LL * 1024 * 1024;
const size_t MAX_FILE_COUNT = 2000;

std::string jsTrim(const std::string& s) {
    size_t b = 0, e = s.size();
    auto isWs = [](char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
    };
    while (b < e && isWs(s[b])) b++;
    while (e > b && isWs(s[e - 1])) e--;
    return s.substr(b, e - b);
}

// Node's exitCode: the close event's code, null when the child was killed by
// a signal (our ShellResult.codeNull).
Json exitCodeJson(const ShellResult& r) {
    return r.codeNull ? Json::null() : Json::number(static_cast<double>(r.exitCode));
}

bool exitCodeEqual(const ShellResult& a, const ShellResult& b) {
    if (a.codeNull != b.codeNull) return false;
    return a.codeNull || a.exitCode == b.exitCode;
}

}  // namespace

std::string bitwinRun(const BitwinRunArgs& args) {
    std::string command = jsTrim(args.command);
    if (command.empty()) throw std::runtime_error("command must be a non-empty string.");
    double timeoutMs = args.hasTimeout ? args.timeoutMs : static_cast<double>(DEFAULT_TIMEOUT_MS);
    if (!(timeoutMs > 0)) throw std::runtime_error("timeoutMs must be a positive number.");
    std::string cwdPath = pathResolve(args.cwdDir.empty() ? "." : args.cwdDir);
    long long timeout = static_cast<long long>(timeoutMs);

    struct RunState {
        ShellResult shell;
        std::map<std::string, std::string> files;
    };
    RunState runs[2];
    for (int i = 0; i < 2; i++) {
        runs[i].shell = runShellSanitized(command, cwdPath, timeout, OUTPUT_CAP_BYTES);
        runs[i].files = hashTree(cwdPath, MAX_FILE_BYTES, MAX_FILE_COUNT);
    }

    Json divergences = Json::array();
    if (!exitCodeEqual(runs[0].shell, runs[1].shell)) {
        Json d = Json::object();
        d.set("kind", Json::string("exit_code"));
        d.set("run1", exitCodeJson(runs[0].shell));
        d.set("run2", exitCodeJson(runs[1].shell));
        divergences.push(std::move(d));
    }
    if (runs[0].shell.stdoutHash != runs[1].shell.stdoutHash) {
        Json d = Json::object();
        d.set("kind", Json::string("stdout"));
        d.set("run1", Json::string(runs[0].shell.stdoutHash.substr(0, 16)));
        d.set("run2", Json::string(runs[1].shell.stdoutHash.substr(0, 16)));
        divergences.push(std::move(d));
    }
    if (runs[0].shell.stderrHash != runs[1].shell.stderrHash) {
        Json d = Json::object();
        d.set("kind", Json::string("stderr"));
        d.set("run1", Json::string(runs[0].shell.stderrHash.substr(0, 16)));
        d.set("run2", Json::string(runs[1].shell.stderrHash.substr(0, 16)));
        divergences.push(std::move(d));
    }

    // Array.from(new Set([...run1.files.keys(), ...run2.files.keys()])).sort():
    // default sort compares UTF-16 code units, so jsStringLess is the
    // comparator rather than the std::map byte order.
    std::vector<std::string> keys;
    keys.reserve(runs[0].files.size() + runs[1].files.size());
    for (const auto& kv : runs[0].files) keys.push_back(kv.first);
    for (const auto& kv : runs[1].files) keys.push_back(kv.first);
    std::sort(keys.begin(), keys.end(), jsStringLess);
    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
    for (const std::string& key : keys) {
        auto h1 = runs[0].files.find(key);
        auto h2 = runs[1].files.find(key);
        if (h1 != runs[0].files.end() && h2 != runs[1].files.end() && h1->second == h2->second) {
            continue;
        }
        Json d = Json::object();
        if (h1 == runs[0].files.end()) {
            d.set("kind", Json::string("file_added"));
            d.set("path", Json::string(key));
            d.set("hash2", Json::string(h2->second.substr(0, 16)));
        } else if (h2 == runs[1].files.end()) {
            d.set("kind", Json::string("file_removed"));
            d.set("path", Json::string(key));
            d.set("hash1", Json::string(h1->second.substr(0, 16)));
        } else {
            d.set("kind", Json::string("file_hash"));
            d.set("path", Json::string(key));
            d.set("run1", Json::string(h1->second.substr(0, 16)));
            d.set("run2", Json::string(h2->second.substr(0, 16)));
        }
        divergences.push(std::move(d));
    }

    Json out = Json::object();
    out.set("verdict", Json::string(divergences.arr.empty() ? "bit_identical" : "divergent"));
    out.set("command", Json::string(command));
    out.set("cwd", Json::string(cwdPath));
    {
        Json env = Json::object();
        Json fixed = Json::object();
        fixed.set("TZ", Json::string("UTC"));
        fixed.set("LC_ALL", Json::string("C"));
        fixed.set("SOURCE_DATE_EPOCH", Json::string("946684800"));
        fixed.set("PYTHONHASHSEED", Json::string("0"));
        env.set("fixed", std::move(fixed));
        Json stripped = Json::array();
        for (const char* s : {"TZ", "LANG", "LC_*", "TERM", "COLUMNS", "LINES", "SESSIONNAME"}) {
            stripped.push(Json::string(s));
        }
        env.set("stripped", std::move(stripped));
        out.set("env", std::move(env));
    }
    {
        Json runsJson = Json::array();
        for (const RunState& r : runs) {
            Json entry = Json::object();
            entry.set("exitCode", exitCodeJson(r.shell));
            entry.set("timedOut", Json::boolean(r.shell.timedOut));
            entry.set("aborted", Json::boolean(false));
            entry.set("stdoutHash", Json::string(r.shell.stdoutHash.substr(0, 16)));
            entry.set("stderrHash", Json::string(r.shell.stderrHash.substr(0, 16)));
            entry.set("stdoutBytes", Json::number(static_cast<double>(r.shell.stdoutBytes)));
            entry.set("stderrBytes", Json::number(static_cast<double>(r.shell.stderrBytes)));
            entry.set("durationMs", Json::number(static_cast<double>(r.shell.durationMs)));
            entry.set("fileCount", Json::number(static_cast<double>(r.files.size())));
            runsJson.push(std::move(entry));
        }
        out.set("runs", std::move(runsJson));
    }
    out.set("checkedFiles", Json::number(static_cast<double>(keys.size())));
    out.set("divergences", std::move(divergences));
    out.set("note",
            Json::string(
                "durationMs is reported but excluded from the verdict: timing is not a content "
                "channel."));
    return out.dump();
}

}  // namespace dship
