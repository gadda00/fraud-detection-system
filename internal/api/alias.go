package api

import "github.com/gadda00/fraud-detection-system/internal/auth"

// principalAlias is a thin alias to avoid a circular import
// (auth.Principal is what the middleware stores; we alias it here so the
// case handlers don't need to import auth directly).
type principalAlias = auth.Principal
