#include <stdio.h>
#include <string.h>
#include <ctype.h>

int contains(char *str, char *sub) {
    return strstr(str, sub) != NULL;
}

int count_digits(char *str) {
    int count = 0;
    for(int i=0; str[i]; i++)
        if(isdigit(str[i])) count++;
    return count;
}

int has_repeated_chars(char *str) {
    for(int i=0; str[i+2]; i++)
        if(str[i]==str[i+1] && str[i]==str[i+2])
            return 1;
    return 0;
}

int check_file(char *input, char rules[][50], int *rule_count) {
    int score = 0;

    if(contains(input, ".exe") || contains(input, ".bat")) {
        score += 30;
        strcpy(rules[(*rule_count)++], "Executable Extension");
    }

    if(contains(input, ".pdf.exe") || contains(input, ".jpg.exe")) {
        score += 40;
        strcpy(rules[(*rule_count)++], "Double Extension");
    }

    if(count_digits(input) > strlen(input)/2) {
        score += 25;
        strcpy(rules[(*rule_count)++], "High Digit Ratio");
    }

    if(has_repeated_chars(input)) {
        score += 20;
        strcpy(rules[(*rule_count)++], "Repeated Characters");
    }

    return score;
}

int check_domain(char *input, char rules[][50], int *rule_count) {
    int score = 0;

    if(contains(input, ".xyz") || contains(input, ".ru")) {
        score += 30;
        strcpy(rules[(*rule_count)++], "Suspicious TLD");
    }

    if(strlen(input) > 15) {
        score += 20;
        strcpy(rules[(*rule_count)++], "Long Domain Name");
    }

    if(has_repeated_chars(input)) {
        score += 25;
        strcpy(rules[(*rule_count)++], "Repeated Characters");
    }

    return score;
}

int check_email(char *input, char rules[][50], int *rule_count) {
    int score = 0;

    if(contains(input, "paypal") || contains(input, "admin")) {
        score += 35;
        strcpy(rules[(*rule_count)++], "Brand Keyword in Local Part");
    }

    if(count_digits(input) > 5) {
        score += 25;
        strcpy(rules[(*rule_count)++], "Excessive Numbers");
    }

    if(contains(input, "@gmail.com") && contains(input, "bank")) {
        score += 40;
        strcpy(rules[(*rule_count)++], "Free Email + Brand Impersonation");
    }

    return score;
}

int check_username(char *input, char rules[][50], int *rule_count) {
    int score = 0;

    if(count_digits(input) > strlen(input)/2) {
        score += 30;
        strcpy(rules[(*rule_count)++], "Digit Dominance");
    }

    if(has_repeated_chars(input)) {
        score += 25;
        strcpy(rules[(*rule_count)++], "Repeated Characters");
    }

    if(contains(input, "official") || contains(input, "admin")) {
        score += 35;
        strcpy(rules[(*rule_count)++], "Impersonation");
    }

    return score;
}

int check_mobile(char *input, char rules[][50], int *rule_count) {
    int score = 0;
    int len = strlen(input);

    if(len < 8 || len > 15) {
        score += 50;
        strcpy(rules[(*rule_count)++], "Invalid Length");
    }

    if(has_repeated_chars(input)) {
        score += 40;
        strcpy(rules[(*rule_count)++], "Repeated Digits");
    }

    if(contains(input, "12345") || contains(input, "00000")) {
        score += 30;
        strcpy(rules[(*rule_count)++], "Sequential Numbers");
    }

    return score;
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        printf("0|Invalid|None\n");
        return 1;
    }

    char *type = argv[1];
    char *input = argv[2];
    int score = 0;
    char rules[10][50]; // max 10 rules
    int rule_count = 0;

    if(strcmp(type,"file")==0)
        score = check_file(input, rules, &rule_count);
    else if(strcmp(type,"domain")==0)
        score = check_domain(input, rules, &rule_count);
    else if(strcmp(type,"email")==0)
        score = check_email(input, rules, &rule_count);
    else if(strcmp(type,"username")==0)
        score = check_username(input, rules, &rule_count);
    else if(strcmp(type,"mobile")==0)
        score = check_mobile(input, rules, &rule_count);

    char *status;
    if(score >= 60) status = "Malicious";
    else if(score >= 30) status = "Suspicious";
    else status = "Normal";

    // Prepare rule-trigger string
    char rule_str[500] = "";
    if(rule_count==0) strcpy(rule_str,"None");
    else {
        for(int i=0;i<rule_count;i++){
            strcat(rule_str, rules[i]);
            if(i<rule_count-1) strcat(rule_str, ", ");
        }
    }

    printf("%d|%s|%s\n", score, status, rule_str);

    return 0;
}
