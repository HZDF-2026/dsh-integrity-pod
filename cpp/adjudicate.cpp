// adjudicate.cpp — see adjudicate.h. Mirrors plugins/dsh-integrity-adjudicate.
#include "adjudicate.h"

#include "jsjson.h"
#include "prereg.h"
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

// record.tolerance ?? 0 — numbers pass through, anything else (null, absent,
// non-numeric tampering) falls back like the nullish coalescing would for
// null/undefined.
double toleranceOf(const Json* v) {
    if (v && v->isNum()) return v->num;
    return 0;
}

}  // namespace

std::string adjudicate(const AdjudicateArgs& args) {
    if (!std::isfinite(args.measured)) {
        throw std::runtime_error("measured must be a finite number.");
    }

    double boundary;
    std::string direction;
    double tolerance;
    std::string boundaryProvenance;
    std::string preregId;
    Json preregChainVerified = Json::null();
    bool hasPreregChainVerified = false;

    if (!args.preregId.empty()) {
        std::string storePath = pathResolve(args.store.empty() ? DEFAULT_STORE : args.store);
        std::vector<Json> records = loadStore(storePath, "prereg");
        const Json* record = nullptr;
        for (const auto& entry : records) {
            const Json* id = entry.get("id");
            if (id && id->isStr() && id->str == args.preregId) {
                record = &entry;
                break;
            }
        }
        if (!record) {
            throw std::runtime_error("prereg record not found: " + args.preregId + " (" +
                                     storePath + ")");
        }
        const Json* rb = record->get("boundary");
        if (!rb || rb->isNull()) {
            throw std::runtime_error("prereg record " + args.preregId +
                                     " carries no numeric boundary; register one before adjudicating.");
        }
        const Json* rid = record->get("id");
        preregId = rid && rid->isStr() ? rid->str : std::string();
        preregChainVerified = Json::boolean(dship::preregChainVerified(records));
        hasPreregChainVerified = true;
        boundary = rb && rb->isNum() ? rb->num : 0;
        if (args.hasDirection) {
            direction = args.direction;
        } else {
            const Json* rd = record->get("direction");
            if (rd && rd->isStr()) direction = rd->str;
        }
        if (direction.empty()) direction = "above";
        if (args.hasTolerance) {
            tolerance = args.tolerance;
        } else {
            tolerance = toleranceOf(record->get("tolerance"));
        }
        boundaryProvenance = "preregistered";
    } else {
        if (!args.hasBoundary || !std::isfinite(args.boundary)) {
            throw std::runtime_error("Provide preregId (preferred) or an explicit numeric boundary.");
        }
        boundary = args.boundary;
        direction = args.hasDirection ? args.direction : "above";
        tolerance = args.hasTolerance ? args.tolerance : 0;
        boundaryProvenance = "post-hoc";
    }

    if (direction != "above" && direction != "below") {
        throw std::runtime_error("direction must be \"above\" or \"below\".");
    }
    if (!(tolerance >= 0)) {
        throw std::runtime_error("tolerance must be a non-negative number.");
    }

    double margin = args.measured - boundary;
    double distance = std::fabs(margin);
    std::string verdict;
    if (distance <= tolerance) {
        verdict = "inconclusive";
    } else if (direction == "above") {
        verdict = margin > 0 ? "supported" : "falsified";
    } else {
        verdict = margin < 0 ? "supported" : "falsified";
    }

    Json out = Json::object();
    out.set("verdict", Json::string(verdict));
    std::string claim = jsTrim(args.claim);
    out.set("claim", claim.empty() ? Json::null() : Json::string(claim));
    out.set("measured", Json::number(args.measured));
    out.set("boundary", Json::number(boundary));
    out.set("direction", Json::string(direction));
    out.set("tolerance", Json::number(tolerance));
    out.set("margin", Json::number(margin));
    out.set("boundaryProvenance", Json::string(boundaryProvenance));
    out.set("preregId", preregId.empty() ? Json::null() : Json::string(preregId));
    out.set("preregChainVerified",
            hasPreregChainVerified ? std::move(preregChainVerified) : Json::null());
    return out.dump();
}

}  // namespace dship
