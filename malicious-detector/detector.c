#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX_RULES 30
#define RULE_LEN 50
#define INPUT_SCAN_LIMIT 1024

int contains(const char *str, const char *sub) {
    return strstr(str, sub) != NULL;
}

int rule_exists(char rules[][RULE_LEN], int rule_count, const char *rule) {
    for (int i = 0; i < rule_count; i++) {
        if (strcmp(rules[i], rule) == 0) {
            return 1;
        }
    }
    return 0;
}

void add_rule(char rules[][RULE_LEN], int *rule_count, const char *rule) {
    if (*rule_count >= MAX_RULES) {
        return;
    }

    if (rule_exists(rules, *rule_count, rule)) {
        return;
    }

    strncpy(rules[*rule_count], rule, RULE_LEN - 1);
    rules[*rule_count][RULE_LEN - 1] = '\0';
    (*rule_count)++;
}

void to_lower_copy(const char *src, char *dst, int dst_size) {
    int i = 0;

    if (dst_size <= 0) {
        return;
    }

    for (; src[i] && i < dst_size - 1; i++) {
        dst[i] = (char)tolower((unsigned char)src[i]);
    }
    dst[i] = '\0';
}

int count_digits(const char *str) {
    int count = 0;
    for (int i = 0; str[i]; i++) {
        if (isdigit((unsigned char)str[i])) {
            count++;
        }
    }
    return count;
}

int has_repeated_chars(const char *str) {
    for (int i = 0; str[i + 2]; i++) {
        if (str[i] == str[i + 1] && str[i] == str[i + 2]) {
            return 1;
        }
    }
    return 0;
}

int count_percent_encoded_sequences(const char *str) {
    int count = 0;

    for (int i = 0; str[i] && str[i + 2]; i++) {
        if (str[i] == '%' &&
            isxdigit((unsigned char)str[i + 1]) &&
            isxdigit((unsigned char)str[i + 2])) {
            count++;
            i += 2;
        }
    }

    return count;
}

int count_hex_escape_sequences(const char *str) {
    int count = 0;

    for (int i = 0; str[i] && str[i + 3]; i++) {
        if (str[i] == '\\' && str[i + 1] == 'x' &&
            isxdigit((unsigned char)str[i + 2]) &&
            isxdigit((unsigned char)str[i + 3])) {
            count++;
            i += 3;
        }
    }

    return count;
}

int has_long_base64_blob(const char *str, int min_len) {
    int run = 0;

    for (int i = 0; str[i]; i++) {
        char c = str[i];
        if (isalnum((unsigned char)c) || c == '+' || c == '/' || c == '=') {
            run++;
            if (run >= min_len) {
                return 1;
            }
        } else {
            run = 0;
        }
    }

    return 0;
}

int count_token_hits(const char *str, const char *tokens[], int token_count) {
    int hits = 0;

    for (int i = 0; i < token_count; i++) {
        if (contains(str, tokens[i])) {
            hits++;
        }
    }

    return hits;
}

int check_file(char *input, char rules[][RULE_LEN], int *rule_count) {
    int score = 0;

    if (contains(input, ".exe") || contains(input, ".bat")) {
        score += 30;
        add_rule(rules, rule_count, "Executable Extension");
    }

    if (contains(input, ".pdf.exe") || contains(input, ".jpg.exe")) {
        score += 40;
        add_rule(rules, rule_count, "Double Extension");
    }

    if (count_digits(input) > (int)(strlen(input) / 2)) {
        score += 25;
        add_rule(rules, rule_count, "High Digit Ratio");
    }

    if (has_repeated_chars(input)) {
        score += 20;
        add_rule(rules, rule_count, "Repeated Characters");
    }

    return score;
}

int check_domain(char *input, char rules[][RULE_LEN], int *rule_count) {
    int score = 0;

    if (contains(input, ".xyz") || contains(input, ".ru")) {
        score += 30;
        add_rule(rules, rule_count, "Suspicious TLD");
    }

    if (strlen(input) > 15) {
        score += 20;
        add_rule(rules, rule_count, "Long Domain Name");
    }

    if (has_repeated_chars(input)) {
        score += 25;
        add_rule(rules, rule_count, "Repeated Characters");
    }

    return score;
}

int check_email(char *input, char rules[][RULE_LEN], int *rule_count) {
    int score = 0;

    if (contains(input, "paypal") || contains(input, "admin")) {
        score += 35;
        add_rule(rules, rule_count, "Brand Keyword in Local Part");
    }

    if (count_digits(input) > 5) {
        score += 25;
        add_rule(rules, rule_count, "Excessive Numbers");
    }

    if (contains(input, "@gmail.com") && contains(input, "bank")) {
        score += 40;
        add_rule(rules, rule_count, "Free Email + Brand Impersonation");
    }

    return score;
}

int check_username(char *input, char rules[][RULE_LEN], int *rule_count) {
    int score = 0;

    if (count_digits(input) > (int)(strlen(input) / 2)) {
        score += 30;
        add_rule(rules, rule_count, "Digit Dominance");
    }

    if (has_repeated_chars(input)) {
        score += 25;
        add_rule(rules, rule_count, "Repeated Characters");
    }

    if (contains(input, "official") || contains(input, "admin")) {
        score += 35;
        add_rule(rules, rule_count, "Impersonation");
    }

    return score;
}

int check_mobile(char *input, char rules[][RULE_LEN], int *rule_count) {
    int score = 0;
    size_t len = strlen(input);

    if (len < 8 || len > 15) {
        score += 50;
        add_rule(rules, rule_count, "Invalid Length");
    }

    if (has_repeated_chars(input)) {
        score += 40;
        add_rule(rules, rule_count, "Repeated Digits");
    }

    if (contains(input, "12345") || contains(input, "00000")) {
        score += 30;
        add_rule(rules, rule_count, "Sequential Numbers");
    }

    return score;
}

int check_payload_pda(char *input, char rules[][RULE_LEN], int *rule_count) {
    int score = 0;
    char stack[INPUT_SCAN_LIMIT];
    int top = -1;
    int max_depth = 0;
    int mismatch = 0;
    int in_single_quote = 0;
    int in_double_quote = 0;
    int escaped = 0;
    int operator_count = 0;
    int escape_count = 0;
    int symbol_count = 0;
    int alpha_num_count = 0;
    int payload_len = (int)strlen(input);

    for (int i = 0; input[i] && i < INPUT_SCAN_LIMIT - 1; i++) {
        char c = input[i];

        if (isalnum((unsigned char)c)) {
            alpha_num_count++;
        } else if (!isspace((unsigned char)c)) {
            symbol_count++;
        }

        if (!escaped && c == '\\') {
            escape_count++;
            escaped = 1;
            continue;
        }

        if (!in_double_quote && c == '\'' && !escaped) {
            in_single_quote = !in_single_quote;
        } else if (!in_single_quote && c == '"' && !escaped) {
            in_double_quote = !in_double_quote;
        }

        if (!in_single_quote && !in_double_quote) {
            if (c == '|' || c == '&' || c == ';' || c == '$' || c == '<' || c == '>') {
                operator_count++;
            }

            if (c == '(' || c == '{' || c == '[') {
                if (top < INPUT_SCAN_LIMIT - 2) {
                    stack[++top] = c;
                    if (top + 1 > max_depth) {
                        max_depth = top + 1;
                    }
                } else {
                    mismatch = 1;
                }
            } else if (c == ')' || c == '}' || c == ']') {
                char expected = (c == ')') ? '(' : (c == '}') ? '{' : '[';
                if (top < 0 || stack[top] != expected) {
                    mismatch = 1;
                } else {
                    top--;
                }
            }
        }

        escaped = 0;
    }

    if (mismatch || top != -1 || in_single_quote || in_double_quote) {
        score += 35;
        add_rule(rules, rule_count, "Unbalanced Delimiters");
    }

    if (max_depth >= 4) {
        score += 20;
        add_rule(rules, rule_count, "Deep Nesting");
    }

    if (operator_count >= 3) {
        score += 20;
        add_rule(rules, rule_count, "Chained Operators");
    }

    if (operator_count >= 6) {
        score += 10;
        add_rule(rules, rule_count, "Operator Burst");
    }

    if (payload_len >= 20 && symbol_count * 100 >= payload_len * 45) {
        score += 15;
        add_rule(rules, rule_count, "High Symbol Density");
    }

    char lower[INPUT_SCAN_LIMIT];
    to_lower_copy(input, lower, INPUT_SCAN_LIMIT);

    const char *execution_tokens[] = {
        "powershell",
        "cmd.exe",
        "wget",
        "curl",
        "base64",
        "frombase64string",
        "invoke-expression",
        "iex",
        "eval(",
        "python -c",
        "perl -e",
        "bash -c",
        "sh -c",
        "nc -e",
        "rundll32",
        "regsvr32",
        "mshta",
        "certutil",
        "<script",
        "javascript:",
        "onerror=",
        "fromcharcode"
    };

    const char *network_tokens[] = {
        "http://",
        "https://",
        "ftp://",
        "/dev/tcp/",
        "pastebin",
        "raw.githubusercontent.com",
        "bit.ly",
        "tinyurl"
    };

    const char *injection_tokens[] = {
        "union select",
        " or 1=1",
        "drop table",
        "document.cookie",
        "<iframe",
        "onload=",
        "../../",
        "..\\"
    };

    const char *persistence_tokens[] = {
        "schtasks",
        "crontab",
        "startup",
        "autorun",
        ".ssh/authorized_keys",
        "registry run",
        "reg add",
        "/etc/passwd"
    };

    int execution_hits = count_token_hits(
        lower,
        execution_tokens,
        (int)(sizeof(execution_tokens) / sizeof(execution_tokens[0]))
    );
    int network_hits = count_token_hits(
        lower,
        network_tokens,
        (int)(sizeof(network_tokens) / sizeof(network_tokens[0]))
    );
    int injection_hits = count_token_hits(
        lower,
        injection_tokens,
        (int)(sizeof(injection_tokens) / sizeof(injection_tokens[0]))
    );
    int persistence_hits = count_token_hits(
        lower,
        persistence_tokens,
        (int)(sizeof(persistence_tokens) / sizeof(persistence_tokens[0]))
    );

    int percent_encoded = count_percent_encoded_sequences(lower);
    int hex_escapes = count_hex_escape_sequences(input);
    int base64_blob = has_long_base64_blob(input, 24);

    if (execution_hits >= 2) {
        score += 35;
        add_rule(rules, rule_count, "Execution Token Cluster");
    } else if (execution_hits == 1) {
        score += 15;
        add_rule(rules, rule_count, "Execution Token Detected");
    }

    if (network_hits > 0 && execution_hits > 0) {
        score += 25;
        add_rule(rules, rule_count, "Download and Execute Pattern");
    } else if (network_hits > 0) {
        score += 10;
        add_rule(rules, rule_count, "Remote Fetch Indicator");
    }

    if (injection_hits >= 2) {
        score += 25;
        add_rule(rules, rule_count, "Injection Pattern Cluster");
    } else if (injection_hits == 1) {
        score += 15;
        add_rule(rules, rule_count, "Injection Primitive");
    }

    if (contains(lower, "../") || contains(lower, "..\\") || contains(lower, "%2e%2e")) {
        score += 20;
        add_rule(rules, rule_count, "Path Traversal Pattern");
    }

    if (persistence_hits > 0) {
        score += 15;
        add_rule(rules, rule_count, "Persistence Indicator");
    }

    if (contains(lower, "$(") || contains(input, "`")) {
        score += 25;
        add_rule(rules, rule_count, "Command Substitution Pattern");
    }

    if (base64_blob || percent_encoded >= 2 || hex_escapes >= 2) {
        score += 20;
        add_rule(rules, rule_count, "Obfuscation Encoding");
    }

    if (escape_count >= 5 || hex_escapes >= 3) {
        score += 15;
        add_rule(rules, rule_count, "Excessive Escapes");
    }

    if (payload_len >= 30 && alpha_num_count > 0 &&
        count_digits(input) * 100 >= alpha_num_count * 55) {
        score += 10;
        add_rule(rules, rule_count, "High Numeric Obfuscation");
    }

    return score;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("0|Invalid|None\n");
        return 1;
    }

    char *type = argv[1];
    char *input = argv[2];
    int score = 0;
    char rules[MAX_RULES][RULE_LEN];
    int rule_count = 0;

    if (strcmp(type, "file") == 0) {
        score = check_file(input, rules, &rule_count);
    } else if (strcmp(type, "domain") == 0) {
        score = check_domain(input, rules, &rule_count);
    } else if (strcmp(type, "email") == 0) {
        score = check_email(input, rules, &rule_count);
    } else if (strcmp(type, "username") == 0) {
        score = check_username(input, rules, &rule_count);
    } else if (strcmp(type, "mobile") == 0) {
        score = check_mobile(input, rules, &rule_count);
    } else if (strcmp(type, "payload") == 0) {
        score = check_payload_pda(input, rules, &rule_count);
    } else {
        printf("0|Invalid Type|None\n");
        return 1;
    }

    if (score > 100) {
        score = 100;
    } else if (score < 0) {
        score = 0;
    }

    char *status;
    if (score >= 60) {
        status = "Malicious";
    } else if (score >= 30) {
        status = "Suspicious";
    } else {
        status = "Normal";
    }

    // Prepare rule-trigger string
    char rule_str[1800] = "";
    if (rule_count == 0) {
        strcpy(rule_str, "None");
    }
    else {
        for (int i = 0; i < rule_count; i++) {
            size_t remaining = sizeof(rule_str) - strlen(rule_str) - 1;
            if (remaining > 0) {
                strncat(rule_str, rules[i], remaining);
            }

            if (i < rule_count - 1) {
                remaining = sizeof(rule_str) - strlen(rule_str) - 1;
                if (remaining > 0) {
                    strncat(rule_str, ", ", remaining);
                }
            }
        }
    }

    printf("%d|%s|%s\n", score, status, rule_str);

    return 0;
}
