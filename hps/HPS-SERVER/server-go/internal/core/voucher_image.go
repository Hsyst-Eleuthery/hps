package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"image"
	"image/color"
	"image/png"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

const (
	voucherWidth  = 800
	voucherHeight = 400
	qrSize        = 120
)

func GenerateVoucherImage(voucherID string, value int, issuer string, owner string) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, voucherWidth, voucherHeight))
	drawBackground(img)
	drawBorder(img)
	drawValue(img, value)
	drawHPSLabel(img)

	idDisplay := voucherID
	if len(idDisplay) > 8 {
		idDisplay = idDisplay[:8]
	}
	drawText(img, voucherWidth/2, voucherHeight-30, idDisplay, color.RGBA{200, 180, 255, 255})
	drawText(img, 30, 60, "Issuer: "+truncateStr(issuer, 30), color.RGBA{180, 160, 220, 255})
	drawText(img, 30, 80, "Owner: "+truncateStr(owner, 30), color.RGBA{180, 160, 220, 255})
	drawQRCode(img, voucherWidth-qrSize-30, 30, voucherID)

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func drawBackground(img *image.RGBA) {
	for y := 0; y < voucherHeight; y++ {
		t := float64(y) / float64(voucherHeight)
		r := uint8(80 + t*40)
		g := uint8(20 + t*10)
		b := uint8(140 + t*60)
		for x := 0; x < voucherWidth; x++ {
			img.Set(x, y, color.RGBA{r, g, b, 255})
		}
	}
}

func drawBorder(img *image.RGBA) {
	borderColor := color.RGBA{150, 100, 200, 255}
	for x := 0; x < voucherWidth; x++ {
		img.Set(x, 0, borderColor)
		img.Set(x, 1, borderColor)
		img.Set(x, voucherHeight-1, borderColor)
		img.Set(x, voucherHeight-2, borderColor)
	}
	for y := 0; y < voucherHeight; y++ {
		img.Set(0, y, borderColor)
		img.Set(1, y, borderColor)
		img.Set(voucherWidth-1, y, borderColor)
		img.Set(voucherWidth-2, y, borderColor)
	}
}

func drawValue(img *image.RGBA, value int) {
	text := fmt.Sprintf("%d $HPS", value)
	x := voucherWidth/2 - len(text)*4
	drawText(img, x, voucherHeight/2+20, text, color.RGBA{255, 255, 255, 255})

	lineColor := color.RGBA{180, 140, 220, 255}
	for lx := 50; lx < voucherWidth-50; lx++ {
		img.Set(lx, voucherHeight/2+40, lineColor)
		img.Set(lx, voucherHeight/2-40, lineColor)
	}
}

func drawHPSLabel(img *image.RGBA) {
	drawText(img, voucherWidth/2-60, voucherHeight/2-60, "HPS DIGITAL CURRENCY", color.RGBA{200, 180, 255, 255})
}

func drawText(img *image.RGBA, x, y int, text string, clr color.Color) {
	face := basicfont.Face7x13
	d := &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(clr),
		Face: face,
		Dot:  fixed.P(x, y),
	}
	d.DrawString(text)
}

func drawQRCode(img *image.RGBA, x, y int, voucherID string) {
	h := sha256.Sum256([]byte(voucherID))
	cellSize := qrSize / 10
	borderColor := color.RGBA{255, 255, 255, 255}

	for row := 0; row < 10; row++ {
		for col := 0; col < 10; col++ {
			bitIndex := row*10 + col
			byteIndex := bitIndex / 8
			bitOffset := bitIndex % 8
			if byteIndex < len(h) && (h[byteIndex]>>uint(bitOffset))&1 == 1 {
				for dy := 0; dy < cellSize; dy++ {
					for dx := 0; dx < cellSize; dx++ {
						img.Set(x+col*cellSize+dx, y+row*cellSize+dy, borderColor)
					}
				}
			}
		}
	}
}

func AttachVoucherImageToJSON(voucher map[string]any) {
	voucherID := ""
	if id, ok := voucher["voucher_id"].(string); ok {
		voucherID = id
	}
	value := 0
	payload, _ := voucher["payload"].(map[string]any)
	if payload != nil {
		if v, ok := payload["value"].(float64); ok {
			value = int(v)
		}
	}
	issuer := ""
	if payload != nil {
		issuer, _ = payload["issuer"].(string)
	}
	owner := ""
	if payload != nil {
		owner, _ = payload["owner"].(string)
	}

	if voucherID == "" || value <= 0 {
		return
	}

	imgBytes, err := GenerateVoucherImage(voucherID, value, issuer, owner)
	if err != nil {
		return
	}
	voucher["voucher_image"] = base64.StdEncoding.EncodeToString(imgBytes)
	voucher["voucher_image_format"] = "image/png"
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func safeIDDisplay(voucherID string) string {
	if len(voucherID) > 8 {
		return voucherID[:8]
	}
	return voucherID
}

func RenderVoucherHTMLWithImage(voucher map[string]any) string {
	voucherID := ""
	if id, ok := voucher["voucher_id"].(string); ok {
		voucherID = id
	}
	value := 0
	payload, _ := voucher["payload"].(map[string]any)
	if payload != nil {
		if v, ok := payload["value"].(float64); ok {
			value = int(v)
		}
	}

	imgData := ""
	if img, ok := voucher["voucher_image"].(string); ok {
		imgData = img
	}

	imgTag := ""
	if imgData != "" {
		imgTag = fmt.Sprintf(`<img src="data:image/png;base64,%s" style="max-width:100%%;border-radius:8px;margin:10px 0;" />`, imgData)
	}

	issuerStr := ""
	ownerStr := ""
	if payload != nil {
		issuerStr, _ = payload["issuer"].(string)
		ownerStr, _ = payload["owner"].(string)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Voucher $HPS - %d</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#1a0a2e;color:#fff;font-family:'Segoe UI',sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;padding:15px}
.voucher{background:linear-gradient(135deg,#3d1a6e,#6b21a8);border-radius:16px;padding:30px;max-width:600px;width:100%%;box-shadow:0 8px 32px rgba(0,0,0,.5);text-align:center;border:2px solid #7c3aed}
.value{font-size:3em;font-weight:bold;color:#fff;text-shadow:0 2px 8px rgba(0,0,0,.3);margin:15px 0}
.label{color:#c084fc;font-size:1.2em;margin:10px 0}
.info{color:#a78bfa;font-size:0.9em;margin:5px 0}
.id{color:#7c3aed;font-family:monospace;font-size:0.8em;margin-top:20px;word-break:break-all}
.header{font-size:0.7em;color:#9ca3af;margin-bottom:10px;text-transform:uppercase;letter-spacing:2px}
</style></head>
<body>
<div class="voucher">
<div class="header">HPS DIGITAL CURRENCY</div>
%s
<div class="value">%d $HPS</div>
<div class="label">CEDULA DIGITAL</div>
<div class="info">ID: %s</div>
<div class="info">Issuer: %s</div>
<div class="info">Owner: %s</div>
<div class="id">%s</div>
</div>
</body></html>`,
		value,
		imgTag,
		value,
		safeIDDisplay(voucherID),
		html.EscapeString(truncateStr(issuerStr, 40)),
		html.EscapeString(truncateStr(ownerStr, 40)),
		html.EscapeString(voucherID),
	)
}
