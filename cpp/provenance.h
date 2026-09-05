// provenance.h — dsh-integrity-provenance: artifact provenance records.
#ifndef dship_PROVENANCE_H
#define dship_PROVENANCE_H

#include <string>

namespace dship {

struct ProvenanceRecordArgs {
    std::string artifact;
    std::string inputs;    // JSON array string or comma/newline separated list
    std::string pipeline;
    std::string store;     // empty -> ".integrity/provenance.jsonl"
};

std::string provenanceRecord(const ProvenanceRecordArgs& args);

struct ProvenanceVerifyArgs {
    std::string id;
    std::string rerun;         // empty -> no rerun
    std::string cwdDir;        // empty -> process cwd
    bool hasTimeout = false;
    long long timeoutMs = 0;   // default 120000
    std::string store;
};

std::string provenanceVerify(const ProvenanceVerifyArgs& args);

}  // namespace dship

#endif  // dship_PROVENANCE_H
