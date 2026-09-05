// prereg.cpp — see prereg.h. Mirrors plugins/dsh-integrity-prereg/index.js.
#include "prereg.h"

#include "jsjson.h"
#include "sha256.h"
#include "store.h"
#include "util.h"

#include <cmath>
#include <stdexcept>

namespace dship {

namespace {

const char* DEFAULT_STORE = ".integrity/prereg.jsonl";

std::string jsTrim(const std::string& s) {
    size_t b = 0, e = s.size();
    auto isWs = [](char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
    };
    while (b < e && isWs(s[b])) b++;
    while (e > b && isWs(s[e - 1])) e--;
    return s.substr(b, e - b);
}

// JS strict equality between the stored prevHash field (undefined when the
// key is absent) and the expected value (null for the first record, the
// previous record's hash field otherwise, itself possibly undefined).
bool strictEqualField(const Json* actual, const Json* expected) {
    // undefined === undefined
    if (actual == nullptr && expected == nullptr) return true;
    if (actual == nullptr || expected == nullptr) return false;
    if (actual->isNull() && expected->isNull()) return true;
    if (actual->isStr() && expected->isStr()) return actual->str == expected->str;
    if (actual->isBool() && expected->isBool()) return actual->b == expected->b;
    if (actual->isNum() && expected->isNum()) return actual->num == expected->num;
    return false;
}

}  // namespace

std::string preregRegister(const PreregRegisterArgs& args) {
    std::string claim = jsTrim(args.claim);
    if (claim.empty()) throw std::runtime_error("claim must be a non-empty string.");
    std::string direction = args.hasDirection ? args.direction : "above";
    if (direction != "above" && direction != "below") {
        throw std::runtime_error("direction must be \"above\" or \"below\".");
    }
    if (args.hasTolerance && !(args.tolerance >= 0)) {
        throw std::runtime_error("tolerance must be a non-negative number.");
    }
    if (args.hasBoundary && !std::isfinite(args.boundary)) {
        throw std::runtime_error("boundary must be a finite number.");
    }
    std::string storePath = pathResolve(args.store.empty() ? DEFAULT_STORE : args.store);
    std::vector<Json> records = loadStore(storePath, "prereg");

    Json record = Json::object();
    {
        // String(n).padStart(3, '0'): pads only below three digits.
        std::string n = std::to_string(records.size() + 1);
        while (n.size() < 3) n = "0" + n;
        record.set("id", Json::string("PR-" + n));
    }
    record.set("registeredAt", Json::string(nowIso()));
    record.set("claim", Json::string(claim));
    record.set("boundary", args.hasBoundary ? Json::number(args.boundary) : Json::null());
    record.set("direction", Json::string(direction));
    record.set("tolerance", args.hasTolerance ? Json::number(args.tolerance) : Json::null());
    {
        std::string rules = jsTrim(args.decisionRules);
        record.set("decisionRules", rules.empty() ? Json::null() : Json::string(rules));
    }
    if (!records.empty()) {
        const Json* last = records.back().get("hash");
        record.set("prevHash", last ? Json(*last) : Json::null());
    } else {
        record.set("prevHash", Json::null());
    }
    {
        Json payload = buildPreregPayload(record);
        record.set("hash", Json::string(chainHash(payload)));
    }
    appendRecord(storePath, record);

    Json out = Json::object();
    const Json* id = record.get("id");
    const Json* hash = record.get("hash");
    const Json* at = record.get("registeredAt");
    out.set("id", Json(*id));
    out.set("hash", Json(*hash));
    out.set("registeredAt", Json(*at));
    out.set("recordCount", Json::number(static_cast<double>(records.size() + 1)));
    out.set("store", Json::string(storePath));
    return out.dump();
}

std::string preregList(const std::string& store) {
    std::string storePath = pathResolve(store.empty() ? DEFAULT_STORE : store);
    std::vector<Json> records = loadStore(storePath, "prereg");

    Json out = Json::object();
    out.set("store", Json::string(storePath));
    out.set("recordCount", Json::number(static_cast<double>(records.size())));
    Json list = Json::array();
    for (const auto& record : records) {
        Json entry = Json::object();
        if (const Json* v = record.get("id")) entry.set("id", Json(*v));
        if (const Json* v = record.get("claim")) entry.set("claim", Json(*v));
        if (const Json* v = record.get("boundary")) entry.set("boundary", Json(*v));
        if (const Json* v = record.get("direction")) entry.set("direction", Json(*v));
        if (const Json* v = record.get("tolerance")) entry.set("tolerance", Json(*v));
        if (const Json* v = record.get("registeredAt")) entry.set("registeredAt", Json(*v));
        if (const Json* v = record.get("hash")) {
            if (v->isStr()) entry.set("hash", Json::string(v->str.substr(0, 12)));
        }
        list.push(std::move(entry));
    }
    out.set("records", std::move(list));
    return out.dump();
}

bool preregChainVerified(const std::vector<Json>& records) {
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
        if (hash->str != chainHash(buildPreregPayload(record))) return false;
    }
    return true;
}

std::string preregVerify(const std::string& store) {
    std::string storePath = pathResolve(store.empty() ? DEFAULT_STORE : store);
    std::vector<Json> records = loadStore(storePath, "prereg");

    Json out = Json::object();
    out.set("store", Json::string(storePath));
    Json firstMismatch = Json::null();
    bool verified = true;
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
        if (!strictEqualField(record.get("prevHash"), expectedPtr)) {
            verified = false;
            Json m = Json::object();
            if (const Json* v = record.get("id")) m.set("id", Json(*v));
            m.set("line", Json::number(static_cast<double>(i + 1)));
            m.set("reason", Json::string("prevHash mismatch"));
            firstMismatch = std::move(m);
            break;
        }
        const Json* hash = record.get("hash");
        bool hashOk = hash && hash->isStr() && hash->str == chainHash(buildPreregPayload(record));
        if (!hashOk) {
            verified = false;
            Json m = Json::object();
            if (const Json* v = record.get("id")) m.set("id", Json(*v));
            m.set("line", Json::number(static_cast<double>(i + 1)));
            m.set("reason", Json::string("hash mismatch"));
            firstMismatch = std::move(m);
            break;
        }
    }
    out.set("verified", Json::boolean(verified));
    out.set("recordCount", Json::number(static_cast<double>(records.size())));
    out.set("firstMismatch", std::move(firstMismatch));
    return out.dump();
}

}  // namespace dship
