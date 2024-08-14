package buildinfo

import (
	"net/http"

	"github.com/go-chi/render"
)

func BuildInfoHandler(bi BuildInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, bi)
	}
}
