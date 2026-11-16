// Bazarish project (c) 2026
#pragma once

#include "LinkFailure.hpp"

#include <exception>
#include <optional>
#include <stdexcept>
#include <string>

namespace bazarish::client {

enum class FetchFailure;

enum class LocalFailure {
    eNone,
    eInvalidInvite,
    eInvalidAlias,
    eInvalidPairLink,
    eNoRegistry,
    eAccountTooLarge,
    ePairingBusy,
    eStopped,
    eStoppedThere,
    eFileGone,
    eFileUnreadable,
    eFileUnwritable,
    eInternal,
};

class LocalError : public std::runtime_error {
public:
    LocalError(const LocalFailure failure, const std::string& message)
        : std::runtime_error(message)
        , failure(failure)
    {
    }

    LocalFailure failure = LocalFailure::eNone;
};

// One of the two is set once something failed.
struct FailureCause {
    LinkFailure link = LinkFailure::eNone;
    LocalFailure local = LocalFailure::eNone;

    bool operator==(const FailureCause&) const = default;
};

inline FailureCause linkCause(const LinkFailure failure)
{
    FailureCause cause;
    cause.link = failure;
    return cause;
}

inline FailureCause localCause(const LocalFailure failure)
{
    FailureCause cause;
    cause.local = failure;
    return cause;
}

LinkFailure linkFailureOf(FetchFailure failure);
std::optional<FailureCause> carriedCause(const std::exception& error);
FailureCause causeOf(const std::exception& error);

}  // namespace bazarish::client
