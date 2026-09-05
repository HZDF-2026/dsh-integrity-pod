// store.h — JSONL append-only stores shared by prereg/provenance/adjudicate.
#ifndef dship_STORE_H
#define dship_STORE_H

#include "jsjson.h"

#include <string>
#include <vector>

namespace dship {

// loadStore from the plugins: JSON per non-empty line, throwing
// `<kind> store corrupted: line N is not JSON (path)` on malformed input.
std::vector<Json> loadStore(const std::string& storePath, const std::string& kind);

// appendRecord: ensure the parent directory exists, then append the record's
// JSON.stringify line with a trailing newline.
void appendRecord(const std::string& storePath, const Json& record);

// Records must keep the exact key order they were written with; building them
// through these helpers mirrors the JS object literals field for field.
Json buildPreregPayload(const Json& record);
Json buildProvenancePayload(const Json& record);

std::string chainHash(const Json& payload);

}  // namespace dship

#endif  // dship_STORE_H
