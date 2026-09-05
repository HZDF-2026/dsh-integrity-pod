// cli.cpp — drives the dsh-integrity-pod plugin cores from the command line:
// prereg / adjudicate / provenance / bitwin / guardrail subcommands.
#include "adjudicate.h"
#include "bitwin.h"
#include "guardrail.h"
#include "prereg.h"
#include "provenance.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstdio>

namespace {

void out(const std::string& s) {
    std::fwrite(s.data(), 1, s.size(), stdout);
    std::fputc('\n', stdout);
}

void errOut(const std::string& s) {
    std::fwrite(s.data(), 1, s.size(), stderr);
    std::fputc('\n', stderr);
}

[[noreturn]] void fail(const std::string& message) {
    errOut("error: " + message);
    std::exit(2);
}

std::string usage() {
    return "dsh-integrity-pod v0.1.0 — C++17 port of the research-integrity plugin cores\n"
           "\n"
           "Usage:\n"
           "  dship-integrity prereg register --claim <text> [--boundary <n>]\n"
           "                     [--direction above|below] [--tolerance <n>]\n"
           "                     [--decision-rules <text>] [--store <path>]\n"
           "  dship-integrity prereg list [--store <path>]\n"
           "  dship-integrity prereg verify [--store <path>]\n"
           "  dship-integrity adjudicate --measured <n> [--prereg-id <id>] [--boundary <n>]\n"
           "                     [--direction above|below] [--tolerance <n>] [--claim <text>]\n"
           "                     [--store <path>]\n"
           "  dship-integrity provenance record --artifact <path> [--inputs <list>]\n"
           "                     [--pipeline <text>] [--store <path>]\n"
           "  dship-integrity provenance verify --id <id> [--rerun <cmd>] [--cwd <dir>]\n"
           "                     [--timeout-ms <n>] [--store <path>]\n"
           "  dship-integrity bitwin run --command <cmd> [--cwd <dir>] [--timeout-ms <n>]\n"
           "  dship-integrity guardrail check --tool <name> [--call-id <id>]\n"
           "                     [--args-json <json>] [guardrail config options]\n"
           "  dship-integrity guardrail log-result --tool <name> [--is-error] [--call-id <id>]\n"
           "                     [guardrail config options]\n"
           "  dship-integrity guardrail status [guardrail config options]\n"
           "\n"
           "Guardrail config options:\n"
           "  --mode enforce|audit            screening mode (default enforce)\n"
           "  --extra-deny <regex>            extra deny pattern (repeatable)\n"
           "  --allow <regex>                 allow pattern override (repeatable)\n"
           "  --integrity-store-dir <dir>     protected store directory (default .integrity)\n"
           "  --no-protect-integrity-stores   disable store protection\n"
           "  --no-audit-log                  skip tool_result audit events\n"
           "  --audit-path <path>             audit log path (default .integrity/tool-audit.jsonl)\n"
           "\n"
           "Notes:\n"
           "  - Every subcommand prints the plugin's JSON result on stdout.\n"
           "  - Tool-level errors exit 1 with the plugin's message on stderr.\n"
           "  - The prereg/adjudicate/provenance/bitwin/guardrail cores are bit-exact\n"
           "    ports of plugins/*/index.js, verified by tests/diff_cpp.mjs.\n";
}

std::vector<std::string> sliceFrom(const std::vector<std::string>& argv, size_t i) {
    if (i >= argv.size()) return std::vector<std::string>();
    return std::vector<std::string>(argv.begin() + static_cast<long>(i), argv.end());
}

struct Options {
    std::map<std::string, std::vector<std::string>> values;  // insertion keeps repeats
    std::set<std::string> present;

    std::string single(const std::string& name) const {
        auto it = values.find(name);
        if (it == values.end() || it->second.empty()) return "";
        return it->second.back();
    }
    std::vector<std::string> all(const std::string& name) const {
        auto it = values.find(name);
        if (it == values.end()) return {};
        return it->second;
    }
    bool has(const std::string& name) const {
        return present.count(name) > 0 || values.count(name) > 0;
    }
};

Options parseOptions(const std::vector<std::string>& argv, const std::set<std::string>& valueFlags,
                     const std::string& context) {
    Options opts;
    for (size_t i = 0; i < argv.size(); i++) {
        const std::string& token = argv[i];
        if (token.rfind("--", 0) != 0) {
            fail("unexpected argument for " + context + ": " + token);
        }
        std::string name = token.substr(2);
        if (name.empty()) fail("empty option for " + context);
        if (valueFlags.count(name)) {
            if (i + 1 >= argv.size()) {
                fail("--" + name + " requires a value (" + context + ")");
            }
            opts.values[name].push_back(argv[++i]);
        } else {
            opts.present.insert(name);
        }
    }
    return opts;
}

double parseNumber(const std::string& raw, const std::string& flag) {
    const char* begin = raw.c_str();
    char* end = nullptr;
    double value = std::strtod(begin, &end);
    if (end == begin || *end != '\0') {
        fail("--" + flag + " expects a number, got: " + raw);
    }
    return value;
}

long long parseInteger(const std::string& raw, const std::string& flag) {
    double value = parseNumber(raw, flag);
    if (value != static_cast<double>(static_cast<long long>(value))) {
        fail("--" + flag + " expects an integer, got: " + raw);
    }
    return static_cast<long long>(value);
}

std::string requireValue(const Options& opts, const std::string& name, const std::string& context) {
    std::string v = opts.single(name);
    if (v.empty()) fail("missing required option --" + name + " (" + context + ")");
    return v;
}

// ------------------------------------------------------------------ guardrail

dship::GuardrailConfig guardrailConfigFrom(const dship::GuardrailConfig& defaults,
                                          const Options& opts) {
    dship::GuardrailConfig cfg = defaults;
    if (opts.has("mode")) cfg.mode = opts.single("mode");
    cfg.extraDenyPatterns = opts.all("extra-deny");
    cfg.allowPatterns = opts.all("allow");
    if (opts.has("integrity-store-dir")) {
        cfg.integrityStoreDir = opts.single("integrity-store-dir");
    }
    if (opts.has("no-protect-integrity-stores")) cfg.protectIntegrityStores = false;
    if (opts.has("no-audit-log")) cfg.auditLog = false;
    if (opts.has("audit-path")) cfg.auditPath = opts.single("audit-path");
    return cfg;
}

int cmdGuardrail(const std::vector<std::string>& argv) {
    if (argv.empty()) fail("guardrail requires a subcommand: check, log-result or status");
    std::string sub = argv[0];
    std::vector<std::string> rest = sliceFrom(argv, 1);
    if (sub == "check") {
        std::set<std::string> valueFlags = {"tool",     "call-id", "args-json", "mode",
                                            "extra-deny", "allow",  "integrity-store-dir",
                                            "audit-path"};
        Options opts = parseOptions(rest, valueFlags, "guardrail check");
        std::string tool = requireValue(opts, "tool", "guardrail check");
        out(dship::guardrailCheck(tool, opts.single("call-id"), opts.single("args-json"),
                                  guardrailConfigFrom(dship::GuardrailConfig(), opts)));
        return 0;
    }
    if (sub == "log-result") {
        std::set<std::string> valueFlags = {"tool",    "call-id", "mode", "extra-deny",
                                            "allow", "integrity-store-dir", "audit-path"};
        Options opts = parseOptions(rest, valueFlags, "guardrail log-result");
        std::string tool = requireValue(opts, "tool", "guardrail log-result");
        out(dship::guardrailLogResult(tool, opts.has("is-error"), opts.single("call-id"),
                                      guardrailConfigFrom(dship::GuardrailConfig(), opts)));
        return 0;
    }
    if (sub == "status") {
        std::set<std::string> valueFlags = {"mode", "extra-deny", "allow",
                                            "integrity-store-dir", "audit-path"};
        Options opts = parseOptions(rest, valueFlags, "guardrail status");
        out(dship::guardrailStatus(guardrailConfigFrom(dship::GuardrailConfig(), opts)));
        return 0;
    }
    fail("unknown guardrail subcommand: " + sub);
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) {
        out(usage());
        return 0;
    }
    std::string command = args[0];
    std::vector<std::string> rest = sliceFrom(args, 1);
    try {
        if (command == "prereg") {
            if (rest.empty()) fail("prereg requires a subcommand: register, list or verify");
            std::string sub = rest[0];
            std::vector<std::string> subArgs = sliceFrom(rest, 1);
            if (sub == "register") {
                Options opts =
                    parseOptions(subArgs,
                                 {"claim", "boundary", "direction", "tolerance",
                                  "decision-rules", "store"},
                                 "prereg register");
                dship::PreregRegisterArgs a;
                a.claim = opts.single("claim");
                if (opts.has("boundary")) {
                    a.hasBoundary = true;
                    a.boundary = parseNumber(opts.single("boundary"), "boundary");
                }
                if (opts.has("direction")) {
                    a.hasDirection = true;
                    a.direction = opts.single("direction");
                }
                if (opts.has("tolerance")) {
                    a.hasTolerance = true;
                    a.tolerance = parseNumber(opts.single("tolerance"), "tolerance");
                }
                a.decisionRules = opts.single("decision-rules");
                a.store = opts.single("store");
                out(dship::preregRegister(a));
                return 0;
            }
            if (sub == "list") {
                Options opts = parseOptions(subArgs, {"store"}, "prereg list");
                out(dship::preregList(opts.single("store")));
                return 0;
            }
            if (sub == "verify") {
                Options opts = parseOptions(subArgs, {"store"}, "prereg verify");
                out(dship::preregVerify(opts.single("store")));
                return 0;
            }
            fail("unknown prereg subcommand: " + sub);
        }
        if (command == "adjudicate") {
            Options opts = parseOptions(rest,
                                        {"measured", "prereg-id", "boundary", "direction",
                                         "tolerance", "claim", "store"},
                                        "adjudicate");
            dship::AdjudicateArgs a;
            a.measured = parseNumber(requireValue(opts, "measured", "adjudicate"), "measured");
            a.preregId = opts.single("prereg-id");
            if (opts.has("boundary")) {
                a.hasBoundary = true;
                a.boundary = parseNumber(opts.single("boundary"), "boundary");
            }
            if (opts.has("direction")) {
                a.hasDirection = true;
                a.direction = opts.single("direction");
            }
            if (opts.has("tolerance")) {
                a.hasTolerance = true;
                a.tolerance = parseNumber(opts.single("tolerance"), "tolerance");
            }
            a.claim = opts.single("claim");
            a.store = opts.single("store");
            out(dship::adjudicate(a));
            return 0;
        }
        if (command == "provenance") {
            if (rest.empty()) {
                fail("provenance requires a subcommand: record or verify");
            }
            std::string sub = rest[0];
            std::vector<std::string> subArgs = sliceFrom(rest, 1);
            if (sub == "record") {
                Options opts =
                    parseOptions(subArgs, {"artifact", "inputs", "pipeline", "store"},
                                 "provenance record");
                dship::ProvenanceRecordArgs a;
                a.artifact = opts.single("artifact");
                a.inputs = opts.single("inputs");
                a.pipeline = opts.single("pipeline");
                a.store = opts.single("store");
                out(dship::provenanceRecord(a));
                return 0;
            }
            if (sub == "verify") {
                Options opts = parseOptions(subArgs,
                                           {"id", "rerun", "cwd", "timeout-ms", "store"},
                                           "provenance verify");
                dship::ProvenanceVerifyArgs a;
                a.id = requireValue(opts, "id", "provenance verify");
                a.rerun = opts.single("rerun");
                a.cwdDir = opts.single("cwd");
                if (opts.has("timeout-ms")) {
                    a.hasTimeout = true;
                    a.timeoutMs = parseInteger(opts.single("timeout-ms"), "timeout-ms");
                }
                a.store = opts.single("store");
                out(dship::provenanceVerify(a));
                return 0;
            }
            fail("unknown provenance subcommand: " + sub);
        }
        if (command == "bitwin") {
            if (rest.empty()) fail("bitwin requires the run subcommand");
            std::string sub = rest[0];
            std::vector<std::string> subArgs = sliceFrom(rest, 1);
            if (sub != "run") fail("unknown bitwin subcommand: " + sub);
            Options opts = parseOptions(subArgs, {"command", "cwd", "timeout-ms"}, "bitwin run");
            dship::BitwinRunArgs a;
            a.command = requireValue(opts, "command", "bitwin run");
            a.cwdDir = opts.single("cwd");
            if (opts.has("timeout-ms")) {
                a.hasTimeout = true;
                a.timeoutMs = parseNumber(opts.single("timeout-ms"), "timeout-ms");
            }
            out(dship::bitwinRun(a));
            return 0;
        }
        if (command == "guardrail") {
            return cmdGuardrail(rest);
        }
        if (command == "--help" || command == "-h" || command == "help") {
            out(usage());
            return 0;
        }
        fail("unknown command: " + command);
    } catch (const std::runtime_error& error) {
        errOut("error: " + std::string(error.what()));
        return 1;
    }
}
