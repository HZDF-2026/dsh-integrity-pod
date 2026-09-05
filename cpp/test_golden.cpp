// test_golden.cpp — golden-table tests against tests/cpp/golden.json, which is
// generated from the Node plugin reference by gen_golden.mjs. Every vector
// must reproduce bit-for-bit; paths are normalized the same way on both sides.
#include "adjudicate.h"
#include "guardrail.h"
#include "jsjson.h"
#include "prereg.h"
#include "provenance.h"
#include "sha256.h"
#include "store.h"
#include "util.h"

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;
using dship::Json;

int failures = 0;
int checks = 0;

void report(const std::string& group, const std::string& name, const std::string& expected,
            const std::string& actual) {
    failures++;
    std::fprintf(stderr, "FAIL [%s] %s\n  expected: %s\n  actual:   %s\n", group.c_str(),
                 name.c_str(), expected.c_str(), actual.c_str());
}

void expectEq(const std::string& group, const std::string& name, const std::string& expected,
              const std::string& actual) {
    checks++;
    if (expected != actual) report(group, name, expected, actual);
}

const Json* field(const Json& v, const char* key) {
    return v.isObj() ? v.get(key) : nullptr;
}

std::string join(const fs::path& a, const std::string& b) {
    return (a / b).string();
}

// ------------------------------------------------------------------- io

std::string loadGolden(int argc, char** argv) {
    std::vector<std::string> candidates;
    if (argc > 1) candidates.push_back(argv[1]);
    candidates.push_back("../tests/cpp/golden.json");
    candidates.push_back("tests/cpp/golden.json");
    for (const auto& c : candidates) {
        std::error_code ec;
        if (fs::exists(fs::path(c), ec)) {
            std::ifstream in(c, std::ios::binary);
            if (in) {
                return std::string((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());
            }
        }
    }
    std::fprintf(stderr, "golden.json not found (run from cpp/ or pass its path)\n");
    std::exit(2);
}

// ------------------------------------------------------------------ norm

std::string tmpDir;
std::string cwdDir;

void replaceAll(std::string& s, const std::string& from, const std::string& to) {
    if (from.empty()) return;
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
}

// gen_golden.mjs norm(): <TMP> for the temp dir, <CWD> for the process cwd,
// forward slashes everywhere.
std::string norm(std::string s) {
    for (char& c : s) {
        if (c == '\\') c = '/';
    }
    std::string tmpFwd = tmpDir, cwdFwd = cwdDir;
    for (char& c : tmpFwd) {
        if (c == '\\') c = '/';
    }
    for (char& c : cwdFwd) {
        if (c == '\\') c = '/';
    }
    replaceAll(s, tmpFwd, "<TMP>");
    replaceAll(s, cwdFwd, "<CWD>");
    return s;
}

// -------------------------------------------------------------- fixtures

Json preregRecord(const std::string& id, const Json& claim, const Json& boundary,
                  const std::string& direction, const Json& tolerance, const Json& decisionRules,
                  const Json& prevHash) {
    Json payload = Json::object();
    payload.set("id", Json::string(id));
    payload.set("registeredAt", Json::string("2026-01-15T00:00:00.000Z"));
    payload.set("claim", claim);
    payload.set("boundary", boundary);
    payload.set("direction", Json::string(direction));
    payload.set("tolerance", tolerance);
    payload.set("decisionRules", decisionRules);
    payload.set("prevHash", prevHash);
    Json record = payload;
    record.set("hash", Json::string(dship::sha256Hex(payload.dump())));
    return record;
}

std::string hashOf(const Json& record) {
    const Json* h = record.get("hash");
    return h && h->isStr() ? h->str : std::string();
}

std::vector<Json> validPreregChain() {
    Json r1 = preregRecord("PR-001", Json::string("c1"), Json::number(0.75), "above",
                           Json::number(0.05), Json::null(), Json::null());
    Json r2 = preregRecord("PR-002", Json::string("c2"), Json::number(120), "below", Json::null(),
                           Json::string("fixed"), Json::string(hashOf(r1)));
    return {r1, r2};
}

std::string storeText(const std::vector<Json>& records) {
    std::string out;
    for (size_t i = 0; i < records.size(); i++) {
        if (i) out += "\n";
        out += records[i].dump();
    }
    return out + "\n";
}

std::string adjudicateStore() {
    std::vector<Json> chain = validPreregChain();
    Json r3 = preregRecord("PR-003", Json::string("c3"), Json::null(), "above", Json::null(),
                           Json::null(), Json::string(hashOf(chain[1])));
    chain.push_back(std::move(r3));
    return storeText(chain);
}

std::string tamperedPreregStore() {
    std::vector<Json> chain = validPreregChain();
    Json tampered = chain[0];
    tampered.set("claim", Json::string("rewritten claim"));
    return storeText({tampered, chain[1]});
}

std::string provenanceStore() {
    Json inputs = Json::array();
    {
        Json entry = Json::object();
        entry.set("path", Json::string(join(tmpDir, "input.csv")));
        entry.set("sha256", Json::string(dship::sha256Hex("a,b\n1,2\n")));
        inputs.push(std::move(entry));
    }
    Json r1 = Json::object();
    r1.set("id", Json::string("PV-001"));
    r1.set("recordedAt", Json::string("2026-01-15T00:00:00.000Z"));
    r1.set("artifact", Json::string(join(tmpDir, "model.bin")));
    r1.set("artifactSha256", Json::string(dship::sha256Hex("deterministic artifact bytes\n")));
    r1.set("inputs", std::move(inputs));
    r1.set("pipeline", Json::string("python train.py"));
    r1.set("gitCommit", Json::null());
    r1.set("repoDirty", Json::null());
    r1.set("prevHash", Json::null());
    r1.set("hash", Json::string(dship::sha256Hex(dship::buildProvenancePayload(r1).dump())));

    Json r2 = Json::object();
    r2.set("id", Json::string("PV-002"));
    r2.set("recordedAt", Json::string("2026-01-15T00:00:00.000Z"));
    r2.set("artifact", Json::string(join(tmpDir, "missing.bin")));
    r2.set("artifactSha256", Json::string(dship::sha256Hex("gone")));
    r2.set("inputs", Json::array());
    r2.set("pipeline", Json::string("echo gone"));
    r2.set("gitCommit", Json::string("abc123"));
    r2.set("repoDirty", Json::boolean(true));
    r2.set("prevHash", Json::string(hashOf(r1)));
    r2.set("hash", Json::string(dship::sha256Hex(dship::buildProvenancePayload(r2).dump())));
    return storeText({r1, r2});
}

// ----------------------------------------------------------------- groups

void testSha256(const Json& golden) {
    const Json* vec = field(golden, "sha256");
    if (!vec || !vec->isArr()) return;
    for (const auto& v : vec->arr) {
        const Json* in = field(v, "input");
        const Json* hex = field(v, "hex");
        if (!in || !hex || !in->isStr() || !hex->isStr()) continue;
        expectEq("sha256", in->str, hex->str, dship::sha256Hex(in->str));
    }
}

void testPreregVerify(const Json& golden) {
    const Json* vec = field(golden, "prereg");
    if (!vec) return;
    const Json* cases = field(*vec, "verify");
    if (!cases || !cases->isArr()) return;
    std::vector<Json> chain = validPreregChain();
    Json firstBadPrev = preregRecord("PR-001", Json::string("c1"), Json::number(1), "above",
                                     Json::null(), Json::null(), Json::string("deadbeef"));
    Json badPrev = chain[1];
    badPrev.set("prevHash", Json::string("deadbeef"));
    Json badHash = chain[1];
    badHash.set("claim", Json::string("tampered"));
    Json brokenLine = Json::string("{\"id\"");

    for (const auto& v : cases->arr) {
        const Json* name = field(v, "name");
        const Json* expectOut = field(v, "out");
        const Json* expectErr = field(v, "error");
        if (!name || !name->isStr()) continue;

        std::string path = join(tmpDir, "prereg-" + name->str + ".jsonl");
        if (name->str != "enoent") {
            std::string store;
            if (name->str == "empty-file") store = "";
            else if (name->str == "single") store = storeText({chain[0]});
            else if (name->str == "chain") store = storeText(chain);
            else if (name->str == "first-prev-not-null") store = storeText({firstBadPrev});
            else if (name->str == "prev-hash-mismatch") store = storeText({chain[0], badPrev});
            else if (name->str == "hash-mismatch") store = storeText({chain[0], badHash});
            else if (name->str == "corrupted-line") store = storeText({chain[0], brokenLine});
            else continue;
            dship::writeFileBytes(path, store);
        }

        try {
            std::string outJson = dship::preregVerify(path);
            Json out;
            if (!Json::parse(outJson, out)) {
                report("prereg.verify", name->str, "<valid json>", outJson);
                continue;
            }
            out.set("store", Json::string("<STORE>"));
            std::string expected =
                expectOut ? expectOut->dump() : std::string("<error: " +
                                                            (expectErr && expectErr->isStr()
                                                                 ? expectErr->str
                                                                 : std::string("none")) +
                                                            ">");
            expectEq("prereg.verify", name->str, expected, out.dump());
        } catch (const std::runtime_error& e) {
            if (expectErr && expectErr->isStr()) {
                expectEq("prereg.verify", name->str, expectErr->str, e.what());
            } else {
                report("prereg.verify", name->str, "<no error>",
                       std::string("threw: ") + e.what());
            }
        }
    }
}

void testPreregRegisterErrors(const Json& golden) {
    const Json* vec = field(golden, "prereg");
    if (!vec) return;
    const Json* cases = field(*vec, "registerErrors");
    if (!cases || !cases->isArr()) return;
    for (const auto& v : cases->arr) {
        const Json* name = field(v, "name");
        const Json* expect = field(v, "error");
        if (!name || !name->isStr() || !expect || !expect->isStr()) continue;
        dship::PreregRegisterArgs args;
        if (name->str == "empty-claim") args.claim = "   ";
        else if (name->str == "bad-direction") {
            args.claim = "x";
            args.hasDirection = true;
            args.direction = "sideways";
        } else if (name->str == "negative-tolerance") {
            args.claim = "x";
            args.hasTolerance = true;
            args.tolerance = -0.1;
        } else {
            continue;
        }
        try {
            dship::preregRegister(args);
            report("prereg.registerErrors", name->str, expect->str, "<no error>");
        } catch (const std::runtime_error& e) {
            expectEq("prereg.registerErrors", name->str, expect->str, e.what());
        }
    }
}

void testAdjudicate(const Json& golden) {
    const Json* cases = field(golden, "adjudicate");
    if (!cases || !cases->isArr()) return;
    std::string storePath = join(tmpDir, "adjudicate-store.jsonl");
    dship::writeFileBytes(storePath, adjudicateStore());
    std::string tamperedPath = join(tmpDir, "adjudicate-tampered.jsonl");
    dship::writeFileBytes(tamperedPath, tamperedPreregStore());

    struct Case {
        const char* name;
        double measured;
        const char* preregId;
        bool hasBoundary;
        double boundary;
        bool hasDirection;
        const char* direction;
        bool hasTolerance;
        double tolerance;
        const char* claim;
        const char* store;  // "fix", "tamper" or "" (none)
    };
    const Case table[] = {
        {"supported", 0.8, "PR-001", false, 0, false, "", false, 0, "", "fix"},
        {"inconclusive", 0.76, "PR-001", false, 0, false, "", false, 0, "", "fix"},
        {"falsified", 0.7, "PR-001", false, 0, false, "", false, 0, "", "fix"},
        {"direction-override", 0.7, "PR-001", false, 0, true, "below", false, 0, "", "fix"},
        {"tolerance-override", 0.76, "PR-001", false, 0, false, "", true, 0, "", "fix"},
        {"below-supported", 100, "PR-002", false, 0, false, "", false, 0, "", "fix"},
        {"below-inconclusive", 100, "PR-002", false, 0, false, "", true, 25, "", "fix"},
        {"posthoc", 6, "", true, 5, false, "", false, 0, "", ""},
        {"claim-trimmed", 0.8, "PR-001", false, 0, false, "", false, 0, "  spaced  ", "fix"},
        {"tampered-chain", 0.8, "PR-001", false, 0, false, "", false, 0, "", "tamper"},
        {"missing-boundary", 5, "PR-003", false, 0, false, "", false, 0, "", "fix"},
        {"unknown-prereg", 5, "PR-999", false, 0, false, "", false, 0, "", "fix"},
        {"no-boundary", 5, "", false, 0, false, "", false, 0, "", ""},
        {"bad-direction", 5, "PR-001", false, 0, true, "sideways", false, 0, "", "fix"},
        {"negative-tolerance", 5, "PR-001", false, 0, false, "", true, -1, "", "fix"},
    };

    for (const auto& v : cases->arr) {
        const Json* name = field(v, "name");
        const Json* expectOut = field(v, "out");
        const Json* expectErr = field(v, "error");
        if (!name || !name->isStr()) continue;
        const Case* c = nullptr;
        for (const Case& entry : table) {
            if (name->str == entry.name) {
                c = &entry;
                break;
            }
        }
        if (!c) continue;

        dship::AdjudicateArgs args;
        args.measured = c->measured;
        args.preregId = c->preregId;
        args.hasBoundary = c->hasBoundary;
        args.boundary = c->boundary;
        args.hasDirection = c->hasDirection;
        args.direction = c->direction;
        args.hasTolerance = c->hasTolerance;
        args.tolerance = c->tolerance;
        args.claim = c->claim;
        if (std::string(c->store) == "fix") args.store = storePath;
        else if (std::string(c->store) == "tamper") args.store = tamperedPath;

        try {
            std::string outJson = dship::adjudicate(args);
            Json out;
            if (!Json::parse(outJson, out)) {
                report("adjudicate", name->str, "<valid json>", outJson);
                continue;
            }
            std::string expected =
                expectOut ? expectOut->dump()
                          : std::string("<error: " + (expectErr && expectErr->isStr()
                                                          ? expectErr->str
                                                          : std::string("none")) +
                                            ">");
            expectEq("adjudicate", name->str, expected, out.dump());
        } catch (const std::runtime_error& e) {
            if (expectErr && expectErr->isStr()) {
                expectEq("adjudicate", name->str, norm(expectErr->str), norm(e.what()));
            } else {
                report("adjudicate", name->str, "<no error>",
                       std::string("threw: ") + norm(e.what()));
            }
        }
    }
}

dship::GuardrailConfig guardrailConfigFrom(const Json& config) {
    dship::GuardrailConfig cfg;
    cfg.auditPath = join(tmpDir, "audit.jsonl");
    if (const Json* v = field(config, "mode")) {
        if (v->isStr()) cfg.mode = v->str;
    }
    if (const Json* v = field(config, "integrityStoreDir")) {
        if (v->isStr()) cfg.integrityStoreDir = v->str;
    }
    if (const Json* v = field(config, "protectIntegrityStores")) {
        if (v->isBool()) cfg.protectIntegrityStores = v->b;
    }
    if (const Json* v = field(config, "extraDenyPatterns")) {
        for (const auto& entry : v->arr) {
            if (entry.isStr()) cfg.extraDenyPatterns.push_back(entry.str);
        }
    }
    if (const Json* v = field(config, "allowPatterns")) {
        for (const auto& entry : v->arr) {
            if (entry.isStr()) cfg.allowPatterns.push_back(entry.str);
        }
    }
    return cfg;
}

void testGuardrailCheck(const Json& golden) {
    const Json* vec = field(golden, "guardrail");
    if (!vec) return;
    const Json* cases = field(*vec, "check");
    if (!cases || !cases->isArr()) return;
    for (const auto& v : cases->arr) {
        const Json* name = field(v, "name");
        const Json* tool = field(v, "tool");
        const Json* arguments = field(v, "arguments");
        const Json* config = field(v, "config");
        const Json* expectOut = field(v, "out");
        if (!name || !name->isStr() || !tool || !tool->isStr() || !arguments || !expectOut) continue;
        dship::GuardrailConfig cfg =
            guardrailConfigFrom(config && config->isObj() ? *config : Json::object());
        try {
            std::string outJson = dship::guardrailCheck(tool->str, "", arguments->dump(), cfg);
            expectEq("guardrail.check", name->str, expectOut->dump(), outJson);
        } catch (const std::runtime_error& e) {
            report("guardrail.check", name->str, expectOut->dump(),
                   std::string("threw: ") + e.what());
        }
    }
}

void testGuardrailConfigErrors(const Json& golden) {
    const Json* vec = field(golden, "guardrail");
    if (!vec) return;
    const Json* cases = field(*vec, "configErrors");
    if (!cases || !cases->isArr()) return;
    for (const auto& v : cases->arr) {
        const Json* name = field(v, "name");
        const Json* config = field(v, "config");
        const Json* expect = field(v, "error");
        if (!name || !name->isStr() || !config || !expect || !expect->isStr()) continue;
        dship::GuardrailConfig cfg =
            guardrailConfigFrom(config->isObj() ? *config : Json::object());
        try {
            dship::guardrailCheck("bash", "", "null", cfg);
            report("guardrail.configErrors", name->str, expect->str, "<no error>");
        } catch (const std::runtime_error& e) {
            expectEq("guardrail.configErrors", name->str, expect->str, e.what());
        }
    }
}

void testProvenanceVerify(const Json& golden) {
    const Json* vec = field(golden, "provenance");
    if (!vec) return;
    const Json* cases = field(*vec, "verify");
    if (!cases || !cases->isArr()) return;
    dship::writeFileBytes(join(tmpDir, "model.bin"), "deterministic artifact bytes\n");
    dship::writeFileBytes(join(tmpDir, "input.csv"), "a,b\n1,2\n");
    std::string storePath = join(tmpDir, "provenance-store.jsonl");
    dship::writeFileBytes(storePath, provenanceStore());

    for (const auto& v : cases->arr) {
        const Json* name = field(v, "name");
        const Json* expectOut = field(v, "out");
        const Json* expectErr = field(v, "error");
        if (!name || !name->isStr()) continue;
        std::string id = name->str == "intact" ? "PV-001"
                         : name->str == "missing" ? "PV-002"
                                                   : "PV-999";
        dship::ProvenanceVerifyArgs args;
        args.id = id;
        args.store = storePath;
        try {
            std::string outJson = dship::provenanceVerify(args);
            Json out;
            if (!Json::parse(outJson, out)) {
                report("provenance.verify", name->str, "<valid json>", outJson);
                continue;
            }
            out.set("store", Json::string("<STORE>"));
            if (const Json* artifact = out.get("artifact")) {
                if (artifact->isStr()) out.set("artifact", Json::string(norm(artifact->str)));
            }
            std::string expected =
                expectOut ? expectOut->dump()
                          : std::string("<error: " + (expectErr && expectErr->isStr()
                                                          ? expectErr->str
                                                          : std::string("none")) +
                                            ">");
            expectEq("provenance.verify", name->str, expected, out.dump());
        } catch (const std::runtime_error& e) {
            if (expectErr && expectErr->isStr()) {
                expectEq("provenance.verify", name->str, norm(expectErr->str), norm(e.what()));
            } else {
                report("provenance.verify", name->str, "<no error>",
                       std::string("threw: ") + norm(e.what()));
            }
        }
    }
}

void testProvenanceRecordErrors(const Json& golden) {
    const Json* vec = field(golden, "provenance");
    if (!vec) return;
    const Json* cases = field(*vec, "recordErrors");
    if (!cases || !cases->isArr()) return;
    dship::writeFileBytes(join(tmpDir, "model.bin"), "deterministic artifact bytes\n");
    std::string storePath = join(tmpDir, "provenance-store.jsonl");
    dship::writeFileBytes(storePath, provenanceStore());

    for (const auto& v : cases->arr) {
        const Json* name = field(v, "name");
        const Json* expect = field(v, "error");
        if (!name || !name->isStr() || !expect || !expect->isStr()) continue;
        const std::string& n = name->str;
        try {
            if (n == "verify-empty-id") {
                dship::ProvenanceVerifyArgs args;
                args.id = "   ";
                args.store = storePath;
                dship::provenanceVerify(args);
            } else {
                dship::ProvenanceRecordArgs args;
                if (n == "empty-artifact") {
                    args.artifact = "   ";
                    args.pipeline = "p";
                } else if (n == "missing-artifact") {
                    args.artifact = join(tmpDir, "nope.bin");
                    args.pipeline = "p";
                } else if (n == "missing-input") {
                    args.artifact = join(tmpDir, "model.bin");
                    args.pipeline = "p";
                    args.inputs = join(tmpDir, "gone.txt");
                } else if (n == "inputs-bad-json") {
                    args.artifact = join(tmpDir, "model.bin");
                    args.pipeline = "p";
                    args.inputs = "[";
                } else if (n == "inputs-object-entry") {
                    args.artifact = join(tmpDir, "model.bin");
                    args.pipeline = "p";
                    args.inputs = "[{}]";
                } else {
                    continue;
                }
                dship::provenanceRecord(args);
            }
            report("provenance.recordErrors", n, expect->str, "<no error>");
        } catch (const std::runtime_error& e) {
            expectEq("provenance.recordErrors", n, norm(expect->str), norm(e.what()));
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    Json golden;
    if (!Json::parse(loadGolden(argc, argv), golden)) {
        std::fprintf(stderr, "golden.json failed to parse\n");
        return 2;
    }

    {
        std::error_code ec;
        fs::path base = fs::temp_directory_path(ec);
        std::random_device rd;
        fs::path dir = base / ("dship-gold-" + std::to_string(rd()) + "-" +
                               std::to_string(std::time(nullptr)));
        std::error_code mk;
        fs::create_directories(dir, mk);
        tmpDir = dir.string();
    }
    cwdDir = dship::cwd();

    testSha256(golden);
    testPreregVerify(golden);
    testPreregRegisterErrors(golden);
    testAdjudicate(golden);
    testGuardrailCheck(golden);
    testGuardrailConfigErrors(golden);
    testProvenanceVerify(golden);
    testProvenanceRecordErrors(golden);

    if (!tmpDir.empty()) {
        std::error_code ec;
        fs::remove_all(fs::path(tmpDir), ec);
    }
    std::printf("golden: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
