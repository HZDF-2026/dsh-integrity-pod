// provenance.cpp — see provenance.h. Mirrors plugins/dsh-integrity-provenance.
#include "provenance.h"

#include "jsjson.h"
#include "sha256.h"
#include "store.h"
#include "util.h"

#include <stdexcept>

namespace dship {

namespace {

const char* DEFAULT_STORE = ".integrity/provenance.jsonl";
const long long DEFAULT_TIMEOUT_MS = 120000;

std::string jsTrim(const std::string& s) {
    size_t b = 0, e = s.size();
    auto isWs = [](char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
    };
    while (b < e && isWs(s[b])) b++;
    while (e > b && isWs(s[e - 1])) e--;
    return s.substr(b, e - b);
}

// String(value): the ECMA-262 ToString used by parseInputs on array entries.
std::string jsStringOf(const Json& v) {
    switch (v.t) {
        case Json::T::Str:
            return v.str;
        case Json::T::Num:
            return jsNumberToString(v.num);
        case Json::T::Bool:
            return v.b ? "true" : "false";
        case Json::T::Null:
            return "null";
        case Json::T::Arr: {
            // Array.prototype.join: null/undefined elements become "".
            std::string out;
            for (size_t i = 0; i < v.arr.size(); i++) {
                if (i) out += ",";
                if (v.arr[i].isNull()) continue;
                out += jsStringOf(v.arr[i]);
            }
            return out;
        }
        case Json::T::Obj:
            return "[object Object]";
    }
    return std::string();
}

// parseInputs: JSON array string or comma/newline separated path list.
std::vector<std::string> parseInputs(const std::string& raw) {
    if (raw.empty()) return {};
    std::string trimmed = jsTrim(raw);
    if (!trimmed.empty() && trimmed[0] == '[') {
        Json parsed;
        if (!Json::parse(trimmed, parsed)) {
            throw std::runtime_error(
                "inputs must be a JSON array string or a comma/newline separated path list.");
        }
        if (!parsed.isArr()) {
            throw std::runtime_error("inputs JSON must be an array of path strings.");
        }
        std::vector<std::string> out;
        for (const auto& entry : parsed.arr) {
            std::string s = jsTrim(jsStringOf(entry));
            if (!s.empty()) out.push_back(s);
        }
        return out;
    }
    std::vector<std::string> out;
    std::string cur;
    for (char c : trimmed) {
        if (c == '\n' || c == ',') {
            std::string entry = jsTrim(cur);
            if (!entry.empty()) out.push_back(entry);
            cur.clear();
        } else {
            cur += c;
        }
    }
    std::string entry = jsTrim(cur);
    if (!entry.empty()) out.push_back(entry);
    return out;
}

bool strictEqualField(const Json* actual, const Json* expected) {
    if (actual == nullptr && expected == nullptr) return true;
    if (actual == nullptr || expected == nullptr) return false;
    if (actual->isNull() && expected->isNull()) return true;
    if (actual->isStr() && expected->isStr()) return actual->str == expected->str;
    if (actual->isBool() && expected->isBool()) return actual->b == expected->b;
    if (actual->isNum() && expected->isNum()) return actual->num == expected->num;
    return false;
}

bool provenanceChainVerified(const std::vector<Json>& records) {
    for (size_t i = 0; i < records.size(); i++) {
        const Json& record = records[i];
        Json expected;
        const Json* expectedPtr;
        if (i == 0) {
            expected = Json::null();
            expectedPtr = &expected;
        } else {
            expectedPtr = records[i - 1].get("hash");
        }
        if (!strictEqualField(record.get("prevHash"), expectedPtr)) return false;
        const Json* hash = record.get("hash");
        if (!hash || !hash->isStr()) return false;
        if (hash->str != chainHash(buildProvenancePayload(record))) return false;
    }
    return true;
}

}  // namespace

std::string provenanceRecord(const ProvenanceRecordArgs& args) {
    if (jsTrim(args.artifact).empty()) {
        throw std::runtime_error("artifact must be a non-empty path.");
    }
    std::string artifactPath = pathResolve(args.artifact);
    std::optional<std::string> artifactSha = sha256FileIfExists(artifactPath);
    if (!artifactSha) {
        throw std::runtime_error("artifact not found: " + artifactPath);
    }

    Json inputs = Json::array();
    for (const std::string& inputPath : parseInputs(args.inputs)) {
        std::string resolved = pathResolve(inputPath);
        std::optional<std::string> hash = sha256FileIfExists(resolved);
        if (!hash) {
            throw std::runtime_error("input not found: " + resolved);
        }
        Json entry = Json::object();
        entry.set("path", Json::string(resolved));
        entry.set("sha256", Json::string(*hash));
        inputs.push(std::move(entry));
    }

    std::string cwdDir = cwd();
    std::optional<std::string> gitCommit = runShellCapture("git rev-parse HEAD", cwdDir);
    std::optional<std::string> status = runShellCapture("git status --porcelain", cwdDir);
    // repoDirty is null when git itself is unavailable, false when clean.
    Json repoDirtyJson = status ? Json::boolean(!status->empty()) : Json::null();
    Json gitCommitJson = gitCommit ? Json::string(*gitCommit) : Json::null();

    std::string storePath = pathResolve(args.store.empty() ? DEFAULT_STORE : args.store);
    std::vector<Json> records = loadStore(storePath, "provenance");

    Json record = Json::object();
    std::string n = std::to_string(records.size() + 1);
    while (n.size() < 3) n = "0" + n;
    record.set("id", Json::string("PV-" + n));
    record.set("recordedAt", Json::string(nowIso()));
    record.set("artifact", Json::string(artifactPath));
    record.set("artifactSha256", Json::string(*artifactSha));
    record.set("inputs", std::move(inputs));
    record.set("pipeline", Json::string(jsTrim(args.pipeline)));
    record.set("gitCommit", std::move(gitCommitJson));
    record.set("repoDirty", std::move(repoDirtyJson));
    if (!records.empty()) {
        const Json* last = records.back().get("hash");
        record.set("prevHash", last ? Json(*last) : Json::null());
    } else {
        record.set("prevHash", Json::null());
    }
    record.set("hash", Json::string(chainHash(buildProvenancePayload(record))));
    appendRecord(storePath, record);

    Json out = Json::object();
    out.set("id", Json::string("PV-" + n));
    out.set("artifact", Json::string(artifactPath));
    out.set("artifactSha256", Json::string(*artifactSha));
    out.set("inputCount",
            Json::number(static_cast<double>(record.get("inputs") ? record.get("inputs")->arr.size()
                                                                   : 0)));
    if (const Json* v = record.get("gitCommit")) out.set("gitCommit", Json(*v));
    if (const Json* v = record.get("repoDirty")) out.set("repoDirty", Json(*v));
    out.set("hash", Json(*record.get("hash")));
    out.set("store", Json::string(storePath));
    return out.dump();
}

std::string provenanceVerify(const ProvenanceVerifyArgs& args) {
    if (jsTrim(args.id).empty()) {
        throw std::runtime_error("id must be a non-empty string.");
    }
    std::string storePath = pathResolve(args.store.empty() ? DEFAULT_STORE : args.store);
    std::vector<Json> records = loadStore(storePath, "provenance");
    const Json* record = nullptr;
    for (const auto& entry : records) {
        const Json* id = entry.get("id");
        if (id && id->isStr() && id->str == jsTrim(args.id)) {
            record = &entry;
            break;
        }
    }
    if (!record) {
        throw std::runtime_error("provenance record not found: " + args.id + " (" + storePath + ")");
    }
    bool chainVerified = provenanceChainVerified(records);

    std::string artifactPath;
    {
        const Json* a = record->get("artifact");
        if (a && a->isStr()) artifactPath = a->str;
    }
    std::string recordedSha;
    {
        const Json* s = record->get("artifactSha256");
        if (s && s->isStr()) recordedSha = s->str;
    }

    if (!jsTrim(args.rerun).empty()) {
        long long timeoutMs = args.hasTimeout ? args.timeoutMs : DEFAULT_TIMEOUT_MS;
        if (!(timeoutMs > 0)) {
            throw std::runtime_error("timeoutMs must be a positive number.");
        }
        std::string runCwd = pathResolve(args.cwdDir.empty() ? "." : args.cwdDir);
        // Node runs and echoes back args.rerun verbatim — no trimming.
        ShellResult run = runShellSanitized(args.rerun, runCwd, timeoutMs, 10LL * 1024 * 1024);
        std::optional<std::string> regenerated = sha256FileIfExists(artifactPath);
        std::string verdict;
        if (!regenerated) verdict = "missing";
        else if (*regenerated == recordedSha) verdict = "reproducible";
        else verdict = "divergent";

        Json out = Json::object();
        out.set("verdict", Json::string(verdict));
        if (const Json* v = record->get("id")) out.set("id", Json(*v));
        out.set("artifact", Json::string(artifactPath));
        out.set("recordedSha256", Json::string(recordedSha));
        out.set("currentSha256", regenerated ? Json::string(*regenerated) : Json::null());
        Json rr = Json::object();
        rr.set("command", Json::string(args.rerun));
        if (run.codeNull) rr.set("exitCode", Json::null());
        else rr.set("exitCode", Json::number(static_cast<double>(run.exitCode)));
        out.set("rerun", std::move(rr));
        out.set("chainVerified", Json::boolean(chainVerified));
        out.set("store", Json::string(storePath));
        return out.dump();
    }

    std::optional<std::string> current = sha256FileIfExists(artifactPath);
    std::string verdict;
    if (!current) verdict = "missing";
    else if (*current == recordedSha) verdict = "intact";
    else verdict = "drifted";

    Json out = Json::object();
    out.set("verdict", Json::string(verdict));
    if (const Json* v = record->get("id")) out.set("id", Json(*v));
    out.set("artifact", Json::string(artifactPath));
    out.set("recordedSha256", Json::string(recordedSha));
    out.set("currentSha256", current ? Json::string(*current) : Json::null());
    out.set("rerun", Json::null());
    out.set("chainVerified", Json::boolean(chainVerified));
    out.set("store", Json::string(storePath));
    return out.dump();
}

}  // namespace dship
