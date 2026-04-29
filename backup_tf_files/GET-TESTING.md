# GET Method Testing — Payload Placement Variants

Four payload-placement variants are supported for GET method tests. The placement is selected at runtime via the `WAF_TEST_GET_PLACEMENT` env var; the YAML file is selected via `WAF_TEST_REQUIREMENTS_FILENAME`.

## Run the four GET variants on EC2

### 1. Existing: GET with query string (default)

```bash
WAF_TEST_REQUIREMENTS_FILENAME=waf_requirements_get.yaml \
  make test-json MODULE=waf_rg_hsbc_custom_v3
```

### 2. Existing: GET with body

```bash
WAF_TEST_GET_PLACEMENT=body \
WAF_TEST_REQUIREMENTS_FILENAME=waf_requirements_get.yaml \
  make test-json MODULE=waf_rg_hsbc_custom_v3
```

(or: `WAF_TEST_GET_WITH_BODY=1` — backwards-compat alias)

### 3. NEW: GET with cookie

```bash
WAF_TEST_GET_PLACEMENT=cookie \
WAF_TEST_REQUIREMENTS_FILENAME=waf_requirements_get_cookie.yaml \
  make test-json MODULE=waf_rg_hsbc_custom_v3
```

### 4. NEW: GET with URI-path injection

```bash
WAF_TEST_GET_PLACEMENT=uri \
WAF_TEST_REQUIREMENTS_FILENAME=waf_requirements_get_uri.yaml \
  make test-json MODULE=waf_rg_hsbc_custom_v3
```

## Wire-shape of each variant

For `juiceshop-0001`, payload `<script>alert(1)</script>` → URL-encoded `%3Cscript%3Ealert%281%29%3C%2Fscript%3E`:

| Placement | Wire form |
|-----------|-----------|
| `query`   | `GET /rest/products/search?q=%3Cscript%3E…` |
| `body`    | `GET /rest/products/search` + `Content-Type: application/json` + body `{"q":"<script>…"}` |
| `cookie`  | `GET /rest/products/search` + `Cookie: q=%3Cscript%3E…` |
| `uri`     | `GET /rest/products/search/%3Cscript%3E…` |
