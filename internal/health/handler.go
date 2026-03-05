package health

import (
	"time"

	"github.com/gofiber/fiber/v3"

	"oss-commands-gateway/internal/config"
)

type Handler struct {
	cfg *config.Config
}

func NewHandler(cfg *config.Config) *Handler {
	return &Handler{cfg: cfg}
}

func (h *Handler) Liveness(c fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":        "ok",
		"service":       "oss-commands-gateway",
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"auth_mode":     h.cfg.AuthMode,
		"state_backend": h.cfg.StateBackend,
	})
}

func (h *Handler) Readiness(c fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":        "ready",
		"state_backend": h.cfg.StateBackend,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	})
}
