#ifndef JSON_H
#define JSON_H

const char *jget(const char *json, const char *key);
const char *jindex(const char *json, int index);
int jstr(const char *json, char *out, int m);
int jdouble(const char *json, double *out);

#endif