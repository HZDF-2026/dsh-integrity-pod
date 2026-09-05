// adjudicate.h — dsh-integrity-adjudicate: boundary adjudication.
#ifndef dship_ADJUDICATE_H
#define dship_ADJUDICATE_H

#include <string>

namespace dship {

struct AdjudicateArgs {
    double measured = 0;
    std::string preregId;    // empty -> absent (both null and "" count as absent)
    bool hasBoundary = false;
    double boundary = 0;
    bool hasDirection = false;
    std::string direction;
    bool hasTolerance = false;
    double tolerance = 0;
    std::string claim;
    std::string store;        // empty -> ".integrity/prereg.jsonl"
};

std::string adjudicate(const AdjudicateArgs& args);

}  // namespace dship

#endif  // dship_ADJUDICATE_H
