// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_NOTIFICATIONS_INTERFACE_H
#define BITCOIN_KERNEL_NOTIFICATIONS_INTERFACE_H

#include <util/translation.h>

#include <cstdint>
#include <exception>
#include <string>
#include <utility>
#include <variant>

class CBlockIndex;
enum class SynchronizationState;

namespace kernel {

//! Result type for use with std::variant to indicate that an operation should be interrupted.
struct Interrupted{};
enum class Warning;


//! Simple result type for functions that need to propagate an interrupt status and don't have other return values.
using InterruptResult = std::variant<std::monostate, Interrupted>;

template <typename T>
bool IsInterrupted(const T& result)
{
    return std::holds_alternative<kernel::Interrupted>(result);
}

/**
 * A base class defining functions for notifying about certain kernel
 * events.
 */
class Notifications
{
public:
    virtual ~Notifications() = default;

    [[nodiscard]] virtual InterruptResult blockTip(SynchronizationState state, const CBlockIndex& index, double verification_progress) { return {}; }
    virtual void headerTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) {}
    virtual void progress(const bilingual_str& title, int progress_percent, bool resume_possible) {}
    virtual void warningSet(Warning id, const bilingual_str& message) {}
    virtual void warningUnset(Warning id) {}

    //! The flush error notification is sent to notify the user that an error
    //! occurred while flushing block data to disk. Kernel code may ignore flush
    //! errors that don't affect the immediate operation it is trying to
    //! perform. Applications can choose to handle the flush error notification
    //! by logging the error, or notifying the user, or triggering an early
    //! shutdown as a precaution against causing more errors.
    virtual void flushError(const bilingual_str& message) {}

    //! The fatal error notification is sent to notify the user when an error
    //! occurs in kernel code that can't be recovered from. After this
    //! notification is sent, whatever function triggered the error should also
    //! return an error code or raise an exception. Applications can choose to
    //! handle the fatal error notification by logging the error, or notifying
    //! the user, or triggering an early shutdown as a precaution against
    //! causing more errors.
    virtual void fatalError(const bilingual_str& message) {}
};

//! Exception thrown when kernel code hits an error it cannot recover from.
//!
//! A FatalError can only be created through Raise(), which fires the
//! fatalError notification before throwing. Catching a FatalError therefore
//! denotes that the notification has already fired and must not be fired
//! again.
//!
//! This deliberately derives from std::exception rather than
//! std::runtime_error, so that existing handlers which translate
//! std::runtime_error into a fatal error do not raise it a second time.
class FatalError : public std::exception
{
public:
    //! Fire the fatalError notification and throw.
    [[noreturn]] static void Raise(Notifications& notifications, bilingual_str message)
    {
        notifications.fatalError(message);
        throw FatalError{std::move(message.original)};
    }

    //! The untranslated error message.
    const char* what() const noexcept override { return m_message.c_str(); }

private:
    explicit FatalError(std::string message) : m_message{std::move(message)} {}

    std::string m_message;
};
} // namespace kernel

#endif // BITCOIN_KERNEL_NOTIFICATIONS_INTERFACE_H
