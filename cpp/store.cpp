// store.cpp — see store.h.
#include "store.h"

#include "sha256.h"
#include "util.h"

#include <fstream>
#include <stdexcept>

namespace dship {

namespace {

std::vector<std::string> splitLines(const std::string& text) {
    std::vector<std::string> lines;
    std::string cur;
    for (size_t i = 0; i < text.size(); i++) {
        if (text[i] == '\n') {
            // \r\n splits like JS /\r?\n/
            if (!cur.empty() && cur.back() == '\r') cur.pop_back();
            lines.push_back(cur);
            cur.clear();
        } else {
            cur += text[i];
        }
    }
    lines.push_back(cur);
    return lines;
}

bool isBlank(const std::string& s) {
    for (char c : s) {
        if (!(c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v')) {
            return false;
        }
    }
    return true;
}

}  // namespace

std::vector<Json> loadStore(const std::string& storePath, const std::string& kind) {
    std::string text;
    {
        std::ifstream in(storePath, std::ios::binary);
        if (!in) return std::vector<Json>();  // ENOENT -> empty store
        text.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }
    std::vector<Json> records;
    std::vector<std::string> lines = splitLines(text);
    for (size_t i = 0; i < lines.size(); i++) {
        if (isBlank(lines[i])) continue;
        Json parsed;
        if (!Json::parse(lines[i], parsed)) {
            throw std::runtime_error(kind + " store corrupted: line " + std::to_string(i + 1) +
                                     " is not JSON (" + storePath + ")");
        }
        records.push_back(std::move(parsed));
    }
    return records;
}

void appendRecord(const std::string& storePath, const Json& record) {
    std::string dir = pathDirname(storePath);
    if (!dir.empty()) mkdirRecursive(dir);
    appendFileBytes(storePath, record.dump() + "\n");
}

Json buildPreregPayload(const Json& record) {
    // JSON.stringify omits keys whose value is undefined, so absent fields on
    // a (possibly tampered) record drop out of the payload the same way.
    Json payload = Json::object();
    if (const Json* v = record.get("id")) payload.set("id", Json(*v));
    if (const Json* v = record.get("registeredAt")) payload.set("registeredAt", Json(*v));
    if (const Json* v = record.get("claim")) payload.set("claim", Json(*v));
    if (const Json* v = record.get("boundary")) payload.set("boundary", Json(*v));
    if (const Json* v = record.get("direction")) payload.set("direction", Json(*v));
    if (const Json* v = record.get("tolerance")) payload.set("tolerance", Json(*v));
    if (const Json* v = record.get("decisionRules")) payload.set("decisionRules", Json(*v));
    if (const Json* v = record.get("prevHash")) payload.set("prevHash", Json(*v));
    return payload;
}

Json buildProvenancePayload(const Json& record) {
    Json payload = Json::object();
    if (const Json* v = record.get("id")) payload.set("id", Json(*v));
    if (const Json* v = record.get("recordedAt")) payload.set("recordedAt", Json(*v));
    if (const Json* v = record.get("artifact")) payload.set("artifact", Json(*v));
    if (const Json* v = record.get("artifactSha256")) payload.set("artifactSha256", Json(*v));
    if (const Json* v = record.get("inputs")) payload.set("inputs", Json(*v));
    if (const Json* v = record.get("pipeline")) payload.set("pipeline", Json(*v));
    if (const Json* v = record.get("gitCommit")) payload.set("gitCommit", Json(*v));
    if (const Json* v = record.get("repoDirty")) payload.set("repoDirty", Json(*v));
    if (const Json* v = record.get("prevHash")) payload.set("prevHash", Json(*v));
    return payload;
}

std::string chainHash(const Json& payload) {
    return sha256Hex(payload.dump());
}

}  // namespace dship
