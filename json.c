#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include "json.h"

const char *jget(const char *json, const char *key)
{
    if (!json) return NULL;
    if (json[0] != '{') return NULL;

    int parens = 1;
    for (int i = 1; json[i] && parens; i++) {
        if (json[i] == '}') parens--;
        if (json[i] == '{') parens++;

        if (json[i] == '"') {
            if (parens == 1 && !strncmp(json + i + 1, key, strlen(key))) {
                int j = i + strlen(key) + 2; // +2 because of opening and closing quotes
                while (isspace(json[j])) j++;
                if (json[j] == ':') {
                    j++;
                    while (isspace(json[j])) j++;
                    return json + j;
                }
            }
            for (i++; json[i] && json[i] != '"'; i++) {
                if (json[i] == '\\' && json[i+1]) i++;
            }
        }
    }

    return NULL;
}

const char *jindex(const char *json, int index)
{
    if (!json) return NULL;
    if (json[0] != '[') return NULL;

    int parens = 1;
    for (int i = 1; json[i] && parens; i++) {
        while (isspace(json[i])) i++;

        if (parens == 1) {
            if (json[i] != ',' && index == 0) return json + i;
            if (json[i] == ',') index--;
        }
        if (json[i] == ']' || json[i] == '}') parens--;
        if (json[i] == '[' || json[i] == '{') parens++;

        if (json[i] == '"') {
            for (i++; json[i] && json[i] != '"'; i++) {
                if (json[i] == '\\' && json[i+1]) i++;
            }
        }
    }

    return NULL;
}

int jstr(const char *json, char *out, int m)
{
    if (!json) return -1;
    if (json[0] != '"') return -1;

    int n = 0;
    for (int i = 1; n < m && json[i] && json[i] != '"'; i++) {
        if (json[i] == '\\' && json[i+1]) i++;
        out[n++] = json[i];
    }
    out[n] = 0;
    return n;
}

int jdouble(const char *json, double *out)
{
    return sscanf(json, " %lf", out) > 0 ? 1 : -1;
}
