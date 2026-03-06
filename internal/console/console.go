package console

import (
	_ "embed"

	"github.com/gofiber/fiber/v3"
)

//go:embed console.html
var consoleHTML string

func Handler(c fiber.Ctx) error {
	c.Set(fiber.HeaderContentType, "text/html; charset=utf-8")
	c.Set(fiber.HeaderCacheControl, "no-cache")
	return c.SendString(consoleHTML)
}
