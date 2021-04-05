//! # Overview
//! This crate simply provides various miscellaneous utilities that are useful in the course of actix-web development, like a function to sanitize control characters from a string (commonly used in user input). See the docs.rs documentation for a complete list of currently available functions.
//!
//! # License
//! Dual licenced under MIT or Apache-2.0 license, the same license as actix-web.
use actix_plus_error::{ResponseError, ResponseResult};
use actix_web::http::StatusCode;
use rand::{thread_rng, Rng};
use std::time::{SystemTime, UNIX_EPOCH};
use unic_ucd_category::GeneralCategory;

/// Returns the current unix time in seconds. This is useful both for when working with external APIs or libraries that expect a UNIX time, and for cleanly keeping track of time in one's own code.
pub fn current_unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

#[test]
fn test_unix_time_increasing_at_proper_rate() {
    use std::thread::sleep;
    use std::time::Duration;

    let first_time = current_unix_time_secs();
    sleep(Duration::from_millis(1000));
    let second_time = current_unix_time_secs();
    assert_eq!(first_time, second_time - 1);
}

/// Generates a secure random string. This is useful for token generation, such as email verification tokens. This string can contain any of the characters in the string "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" with equal probability.
pub fn secure_random_string(len: usize) -> String {
    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    let mut random_string = Vec::new();
    let mut rng = thread_rng();
    random_string.reserve(len);
    for _i in 0..len {
        random_string.push(chars[rng.gen_range(0, chars.len())]);
    }
    String::from_utf8(random_string).expect("Random string contains non-UTF data.")
}

#[test]
fn test_secure_random_strings() {
    let length = 1024;
    let string_1 = secure_random_string(length);
    let string_2 = secure_random_string(length);
    assert_ne!(string_1, string_2);
    assert_eq!(string_1.len(), length);
    assert_eq!(string_2.len(), length);
}

/// Validates a given string to contain only text characters (from any language), and no control characters, thus making it safe to display in a web page IF IT IS THEN PROPERLY ESCAPED, AS AN ADDITIONAL STEP. THIS METHOD DOES NOT ESCAPE FOR HTML, JAVASCRIPT, OR ANY OTHER LANGUAGE.
/// If allow_new_line is set to true, then \n and \r are allowed, but \r is removed.
/// If a string contains control characters (other than \n and \r when allow_new_line is true) then a ResponseResult that allows 400 Bad Request to be propagated is returned. If you prefer to use your own error handling, you can simply match on the Err variant and interpret as documented here.
pub fn validate_and_sanitize_string(string: &str, allow_new_line: bool) -> ResponseResult<String> {
    let mut output = String::new();
    output.reserve(string.len());
    for ch in string.chars() {
        if ch == ' ' || (allow_new_line && ch == '\n') {
            output.push(ch);
        } else if allow_new_line && ch == '\r' {
            //do nothing, remove this character
        } else {
            let ctg = GeneralCategory::of(ch);
            if ctg.is_other() || ctg.is_separator() {
                return Err(ResponseError::StatusCodeError {
                    message: String::from("Input strings for user-supplied content must not contain non-printable characters, excepting newlines in some cases."),
                    code: StatusCode::BAD_REQUEST
                });
            } else {
                output.push(ch);
            }
        }
    }

    Ok(output)
}

#[test]
fn test_string_validation() {
    assert_eq!(
        validate_and_sanitize_string("Test String", false).is_ok(),
        true
    );
    assert_eq!(
        validate_and_sanitize_string("Test String", true).is_ok(),
        true
    );
    assert_eq!(
        validate_and_sanitize_string("Test String\n\r", true).is_ok(),
        true
    );
    assert_eq!(
        validate_and_sanitize_string("Test String\n\r", false).is_ok(),
        false
    );
    assert_eq!(
        validate_and_sanitize_string("Test String\n", true).is_ok(),
        true
    );
    assert_eq!(
        validate_and_sanitize_string("Test String\n", false).is_ok(),
        false
    );
    assert_eq!(
        validate_and_sanitize_string("Test String\t", false).is_ok(),
        false
    );
    assert_eq!(
        validate_and_sanitize_string("Test String\t", true).is_ok(),
        false
    );
    assert_eq!(
        validate_and_sanitize_string("Test\n\rString", true).unwrap(),
        "Test\nString"
    );
}
