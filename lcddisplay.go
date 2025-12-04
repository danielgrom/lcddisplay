// Package main provides a tool for rendering HTML content and system information to an AX206-based LCD display via USB.
//
// This application uses the chromedp library to render HTML pages or URLs into screenshots,
// which are then converted to the appropriate pixel format and transmitted to an AX206 LCD device
// through USB bulk transfers using the SCSI-over-USB protocol.
//
// Features:
//   - Render local HTML files or remote URLs to the LCD display
//   - Support for multiple pixel formats (RGB565, BGR565, BRG565)
//   - Configurable endianness (big/little)
//   - Image rotation (0°, 90°, 180°, 270°)
//   - Loop mode with configurable intervals
//   - Built-in HTTP server providing real-time system information endpoints
//   - Verbose logging for debugging
//
// The system information server exposes various endpoints at http://localhost:8080/system/*
// for monitoring memory, CPU, disk, network, temperature, processes, and other system metrics.
//
// USB Protocol:
// The AX206 device communicates using a custom SCSI-over-USB protocol with:
//   - Vendor ID: 0x1908
//   - Product ID: 0x0102
//   - Bulk OUT endpoint: 0x01
//   - Bulk IN endpoint: 0x81
//
// Command-line flags:
//   --html        Path to local HTML file to render
//   --url         External URL to render
//   --loop        Enable continuous rendering in a loop
//   --interval    Time between renders in loop mode (default: 1s)
//   --format      Pixel format: rgb565, bgr565, or brg565 (default: rgb565)
//   --endian      Byte order: little or big (default: big)
//   --verbose     Enable detailed logging output
//   --rotate      Rotation angle in degrees: 0, 90, 180, or 270 (default: 0)
//   --info        Display LCD resolution and exit
//
// Example usage:
//   lcddisplay --html dashboard.html --loop --interval=5s --format=brg565 --rotate=90
//   lcddisplay --url https://example.com --verbose
//   lcddisplay --info

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/google/gousb"
)

// / USB device parameters
const (
	vid      = 0x1908
	pid      = 0x0102
	endptOut = 0x01
	endptIn  = 0x81
)

// / Command-line flags
var (
	htmlFile     = flag.String("html", "", "Render a local HTML file")
	loop         = flag.Bool("loop", false, "Run in infinite loop")
	info         = flag.Bool("info", false, "Show display information")
	format       = flag.String("format", "rgb565", "Color format: rgb565, bgr565, brg565")
	endian       = flag.String("endian", "big", "Endianness: little or big")
	verbose      = flag.Bool("verbose", false, "Enable verbose logging")
	rotate       = flag.Int("rotate", 0, "Image rotation in degrees (0, 90, 180, 270)")
	interval     = flag.Duration("interval", time.Second, "Interval between renderings in loop mode (e.g., 1000ms, 1s)")
	chromiumPath = flag.String("chromium", "/usr/bin/chromium", "Path to Chromium/Chrome executable")
)

// / AX206 represents the AX206 LCD device and provides methods for communication.
type ax206 struct {
	dev    *gousb.Device
	cfg    *gousb.Config
	intf   *gousb.Interface
	outEP  *gousb.OutEndpoint
	inEP   *gousb.InEndpoint
	width  int
	height int
}

const serverAddr = "127.0.0.1:8080"

// / openAX206 initializes and opens a connection to the AX206 LCD device.
// / ctx: Context for USB operations.
// / Returns: *ax206, error
func openAX206(ctx context.Context) (*ax206, error) {
	usbCtx := gousb.NewContext()
	defer usbCtx.Close()
	dev, err := usbCtx.OpenDeviceWithVIDPID(vid, pid)
	if err != nil {
		return nil, fmt.Errorf("open device: %w, need proper permissions?", err)
	}
	if dev == nil {
		return nil, fmt.Errorf("device %04x:%04x not found", vid, pid)
	}
	cfg, err := dev.Config(1)
	if err != nil {
		dev.Close()
		return nil, err
	}
	intf, err := cfg.Interface(0, 0)
	if err != nil {
		cfg.Close()
		dev.Close()
		return nil, err
	}
	outEP, err := intf.OutEndpoint(endptOut)
	if err != nil {
		intf.Close()
		cfg.Close()
		dev.Close()
		return nil, err
	}
	inEP, err := intf.InEndpoint(endptIn)
	if err != nil {
		intf.Close()
		cfg.Close()
		dev.Close()
		return nil, err
	}

	ax := &ax206{dev: dev, cfg: cfg, intf: intf, outEP: outEP, inEP: inEP}
	w, h, err := ax.getLCDParams()
	if err != nil {
		return nil, err
	}
	ax.width, ax.height = w, h
	return ax, nil
}

// / Close releases resources associated with the AX206 device.
// / Parameters: none
func (a *ax206) Close() {
	if a.intf != nil {
		a.intf.Close()
	}
	if a.cfg != nil {
		a.cfg.Close()
	}
	if a.dev != nil {
		a.dev.Close()
	}
}

// / getLCDParams retrieves the width and height of the LCD display.
// / Width and height of the LCD display.
// / Returns: int, int, error
func (a *ax206) getLCDParams() (int, int, error) {
	excmd := make([]byte, 16)
	excmd[0] = 0xcd
	excmd[5] = 0x02
	reply := make([]byte, 5)
	if err := a.wrapSCSI(excmd, excmd, false, reply, uint32(len(reply))); err != nil {
		return 0, 0, err
	}
	w := int(binary.LittleEndian.Uint16(reply[0:2]))
	h := int(binary.LittleEndian.Uint16(reply[2:4]))
	return w, h, nil
}

// / wrapSCSI sends a SCSI command wrapped in the AX206 USB protocol.
// / cmd is the SCSI command to send.
// / cmdPayload is the payload associated with the command.
// / dirOut indicates the direction of data transfer (true for OUT, false for IN).
// / data is the buffer for data transfer.
// / blockLen is the length of the data to transfer.
// / Returns: error

func (a *ax206) wrapSCSI(cmd []byte, cmdPayload []byte, dirOut bool, data []byte, blockLen uint32) error {
	cbw := make([]byte, 31+16)
	copy(cbw[0:4], []byte("USBC"))
	copy(cbw[4:8], []byte{0xde, 0xad, 0xbe, 0xef})
	binary.LittleEndian.PutUint32(cbw[8:12], blockLen)
	if dirOut {
		cbw[12] = 0x00
	} else {
		cbw[12] = 0x80
	}
	cbw[13] = 0x00
	cbw[14] = byte(len(cmdPayload))
	copy(cbw[15:31], cmdPayload)
	if _, err := a.outEP.Write(cbw); err != nil {
		return err
	}
	if dirOut {
		if data != nil && blockLen > 0 {
			if _, err := a.outEP.Write(data); err != nil {
				return err
			}
		}
	} else {
		if data != nil && blockLen > 0 {
			if _, err := a.inEP.Read(data); err != nil {
				return err
			}
		}
	}
	ack := make([]byte, 13)
	if _, err := a.inEP.Read(ack); err != nil {
		return err
	}
	if string(ack[0:4]) != "USBS" {
		return fmt.Errorf("invalid ACK signature: expected USBS, got %s", string(ack[0:4]))
	}
	if ack[12] != 0x00 {
		return fmt.Errorf("status %02x", ack[12])
	}
	return nil
}

// / blit sends image data to the LCD display within specified coordinates.
// / Parameters: img []byte, x0, y0, x1, y1 int, cmd byte
// / Image data to send.
// / x0, y0: Top-left coordinates.
// / x1, y1: Bottom-right coordinates.
// / cmd: Command byte for the blit operation.
// / Returns: error
func (a *ax206) blit(img []byte, x0, y0, x1, y1 int, cmd byte) error {
	excmd := make([]byte, 16)
	excmd[0] = 0xcd
	excmd[5] = cmd
	excmd[7] = byte(x0 & 0xff)
	excmd[8] = byte(x0 >> 8)
	excmd[9] = byte(y0 & 0xff)
	excmd[10] = byte(y0 >> 8)
	excmd[11] = byte((x1 - 1) & 0xff)
	excmd[12] = byte((x1 - 1) >> 8)
	excmd[13] = byte((y1 - 1) & 0xff)
	excmd[14] = byte((y1 - 1) >> 8)
	return a.wrapSCSI(excmd, excmd, true, img, uint32(len(img)))
}

// / convertPixel converts RGB values to a 16-bit pixel format.
// / r Red component (0-255).
// / g Green component (0-255).
// / b Blue component (0-255).
// / format Pixel format: "rgb565", "bgr565", or "brg565".
// / Returns: uint16
func convertPixel(r, g, b uint8, format string) uint16 {
	switch format {
	case "rgb565":
		return (uint16(r)&0xF8)<<8 | (uint16(g)&0xFC)<<3 | (uint16(b)&0xF8)>>3
	case "bgr565":
		return (uint16(b)&0xF8)<<8 | (uint16(g)&0xFC)<<3 | (uint16(r)&0xF8)>>3
	case "brg565":
		return (uint16(b)&0xF8)<<8 | (uint16(r)&0xFC)<<3 | (uint16(g)&0xF8)>>3
	default:
		// fallback para brg565
		return (uint16(b)&0xF8)<<8 | (uint16(r)&0xFC)<<3 | (uint16(g)&0xF8)>>3
	}
}

// / enableConsoleLogging sets up listeners to capture console messages and exceptions from Chromium.
// / ctx: Context for Chromium operations.
func enableConsoleLogging(ctx context.Context) {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			for _, arg := range e.Args {
				if arg.Value != nil {
					fmt.Printf("[Chromium %s] %s\n", e.Type.String(), arg.Value)
				} else if arg.Description != "" {
					fmt.Printf("[Chromium %s] %s\n", e.Type.String(), arg.Description)
				}
			}
		case *runtime.EventExceptionThrown:
			details := e.ExceptionDetails
			fmt.Printf("[Chromium Exception] %s\n", details.Text)
			if details.Exception != nil && details.Exception.Description != "" {
				fmt.Printf("  %s\n", details.Exception.Description)
			}
			if details.StackTrace != nil {
				for _, frame := range details.StackTrace.CallFrames {
					fmt.Printf("  at %s (%s:%d:%d)\n",
						frame.FunctionName, frame.URL, frame.LineNumber, frame.ColumnNumber)
				}
			}
		}
	})
}

// / rotateImage rotates the given image by the specified angle (90, 180, 270 degrees).
// / img: The image to rotate.
// / angle: Rotation angle in degrees (90, 180, 270).
// / Returns: Rotated image.
func rotateImage(img image.Image, angle int) image.Image {
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()

	switch angle {
	case 90:
		dst := image.NewRGBA(image.Rect(0, 0, h, w))
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				dst.Set(h-y-1, x, img.At(x, y))
			}
		}
		return dst
	case 180:
		dst := image.NewRGBA(image.Rect(0, 0, w, h))
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				dst.Set(w-x-1, h-y-1, img.At(x, y))
			}
		}
		return dst
	case 270:
		dst := image.NewRGBA(image.Rect(0, 0, h, w))
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				dst.Set(y, w-x-1, img.At(x, y))
			}
		}
		return dst
	default:
		return img
	}
}

// / convertToBuffer converts an image to a byte buffer in the specified pixel format and endianess.
// / img: The image to convert.
// / w Width of the image.
// / h Height of the image.
// / format Pixel format: "rgb565", "bgr565", or "brg565".
// / endian Endianness: "little" or "big".
// / Returns: Byte buffer containing the converted image data.
func convertToBuffer(img image.Image, w, h int, format, endian string) []byte {
	buf := make([]byte, w*h*2)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			R := uint8(r >> 8)
			G := uint8(g >> 8)
			B := uint8(b >> 8)
			p := convertPixel(R, G, B, format)
			lo := byte(p & 0xff)
			hi := byte(p >> 8)
			off := (y*w + x) * 2
			if endian == "big" {
				buf[off] = hi
				buf[off+1] = lo
			} else {
				buf[off] = lo
				buf[off+1] = hi
			}
		}
	}
	return buf
}

// / withCORS is a middleware that adds CORS headers to HTTP responses.
// / h is the HTTP handler function to wrap.

var allowedOrigins = map[string]bool{
	"http://localhost:8080": true,
	"http://127.0.0.1:8080": true,
	"null":                  true,
}

func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		h(w, r)
	}
}

// / startSystemInfoServer initializes and starts the HTTP server providing system information endpoints.
func startSystemInfoServer() {
	// Memória
	http.HandleFunc("/system/memory", withCORS(func(w http.ResponseWriter, r *http.Request) {
		v, err := mem.VirtualMemory()
		if err != nil {
			log.Printf("error getting memory info: %v", err)
			http.Error(w, "failed to get memory info", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(v); err != nil {
			log.Printf("error encoding memory info: %v", err)
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))

	// Swap
	http.HandleFunc("/system/swap", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s, err := mem.SwapMemory()
		if err != nil {
			log.Printf("error getting swap info: %v", err)
			http.Error(w, "failed to get swap info", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(s); err != nil {
			log.Printf("error encoding swap info: %v", err)
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))

	// CPU
	http.HandleFunc("/system/cpu", withCORS(func(w http.ResponseWriter, r *http.Request) {
		c, err := cpu.Info()
		if err != nil {
			log.Printf("error getting cpu info: %v", err)
			http.Error(w, "failed to get cpu info", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(c); err != nil {
			log.Printf("error encoding cpu info: %v", err)
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))

	// CPU Percent
	http.HandleFunc("/system/cpu/percent", withCORS(func(w http.ResponseWriter, r *http.Request) {
		p, err := cpu.Percent(time.Second, true)
		if err != nil {
			log.Printf("error getting cpu percent: %v", err)
			http.Error(w, "failed to get cpu percent", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(p); err != nil {
			log.Printf("error encoding cpu percent: %v", err)
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))

	// Disco
	http.HandleFunc("/system/disk", withCORS(func(w http.ResponseWriter, r *http.Request) {
		d, err := disk.Usage("/")
		if err != nil {
			log.Printf("error getting disk usage: %v", err)
			http.Error(w, "failed to get disk usage", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(d); err != nil {
			log.Printf("error encoding disk usage: %v", err)
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))

	// Partições
	http.HandleFunc("/system/disk/partitions", withCORS(func(w http.ResponseWriter, r *http.Request) {
		parts, err := disk.Partitions(true)
		if err != nil {
			log.Printf("error getting disk partitions: %v", err)
			http.Error(w, "failed to get disk partitions", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(parts); err != nil {
			log.Printf("error encoding disk partitions: %v", err)
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))

	// Rede
	http.HandleFunc("/system/net", withCORS(func(w http.ResponseWriter, r *http.Request) {
		io, err := net.IOCounters(true)
		if err != nil {
			log.Printf("error getting net io counters: %v", err)
			http.Error(w, "failed to get net io counters", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(io); err != nil {
			log.Printf("error encoding net io counters: %v", err)
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))

	// Conexões de rede
	http.HandleFunc("/system/net/conns", withCORS(func(w http.ResponseWriter, r *http.Request) {
		conns, err := net.Connections("all")
		if err != nil {
			log.Printf("error getting net connections: %v", err)
			http.Error(w, "failed to get net connections", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(conns); err != nil {
			log.Printf("error encoding net connections: %v", err)
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))

	// Temperatura
	http.HandleFunc("/system/temp", withCORS(func(w http.ResponseWriter, r *http.Request) {
		temps, err := host.SensorsTemperatures()
		if err != nil {
			log.Printf("error getting temperatures: %v", err)
			http.Error(w, "failed to get temperatures", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(temps); err != nil {
			log.Printf("error encoding temperatures: %v", err)
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))

	// Host info
	http.HandleFunc("/system/host", withCORS(func(w http.ResponseWriter, r *http.Request) {
		h, err := host.Info()
		if err != nil {
			log.Printf("error getting host info: %v", err)
			http.Error(w, "failed to get host info", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(h); err != nil {
			log.Printf("error encoding host info: %v", err)
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))

	// Usuários logados
	http.HandleFunc("/system/users", withCORS(func(w http.ResponseWriter, r *http.Request) {
		u, err := host.Users()
		if err != nil {
			log.Printf("error getting users: %v", err)
			http.Error(w, "failed to get users", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(u); err != nil {
			log.Printf("error encoding users: %v", err)
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))

	// Load Average
	http.HandleFunc("/system/load", withCORS(func(w http.ResponseWriter, r *http.Request) {
		l, err := load.Avg()
		if err != nil {
			log.Printf("error getting load avg: %v", err)
			http.Error(w, "failed to get load avg", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(l); err != nil {
			log.Printf("error encoding load avg: %v", err)
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))

	// Processos
	http.HandleFunc("/system/processes", withCORS(func(w http.ResponseWriter, r *http.Request) {
		procs, err := process.Processes()
		if err != nil {
			log.Printf("error getting processes: %v", err)
			http.Error(w, "failed to get processes", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(procs); err != nil {
			log.Printf("error encoding processes: %v", err)
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))

	go func() {
		if *verbose {
			log.Printf("System info server running at //%s", serverAddr)
		}
		if err := http.ListenAndServe(serverAddr, nil); err != nil {
			log.Printf("System info server stopped: %v", err)
		}
	}()
}

// / renderSource renders the given source URL or file path to an image using headless Chromium.
// / src: The source URL or file path to render.
// / w: Width of the rendered image.
// / h: Height of the rendered image.
// / Returns: Rendered image, error
func renderSource(src string, w, h int) (image.Image, error) {
	// Determina o caminho do Chromium
	path := *chromiumPath
	if path == "" {
		path = os.Getenv("CHROMIUM_PATH")
	}
	if path == "" {
		// tenta alguns caminhos comuns
		commonPaths := []string{
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/usr/bin/google-chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
		for _, p := range commonPaths {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}
	if path == "" {
		return nil, fmt.Errorf("no Chromium executable found, set --chromium flag or CHROMIUM_PATH env var")
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(path),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.WindowSize(w, h),
	)

	ctx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	if *verbose {
		enableConsoleLogging(ctx)
	}

	var buf []byte

	// Primeiro monta as tarefas principais
	tasks := chromedp.Tasks{
		chromedp.Navigate(src),
		chromedp.Sleep(100 * time.Millisecond),
		chromedp.FullScreenshot(&buf, 90),
		chromedp.Sleep(100 * time.Millisecond),
	}

	// Executa as tarefas principais
	if err := chromedp.Run(ctx, tasks); err != nil {
		return nil, fmt.Errorf("chromedp tasks failed: %w", err)
	}

	// Agora checa se loadInfo existe e chama se necessário
	var exists bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(`typeof loadInfo === "function"`, &exists)); err != nil {
		return nil, fmt.Errorf("failed to check loadInfo: %w", err)
	}
	if exists {
		if err := chromedp.Run(ctx, chromedp.Evaluate(`loadInfo()`, nil)); err != nil {
			log.Printf("loadInfo() call failed: %v", err)
		}
	} else if *verbose {
		log.Println("loadInfo() not defined in page, skipping")
	}

	// Detecta formato
	if len(buf) >= 8 && bytes.HasPrefix(buf, []byte{0x89, 'P', 'N', 'G'}) {
		return png.Decode(bytes.NewReader(buf))
	} else if len(buf) >= 2 && buf[0] == 0xFF && buf[1] == 0xD8 {
		return jpeg.Decode(bytes.NewReader(buf))
	}

	return nil, fmt.Errorf("unknown format in screenshot")
}

// / main is the entry point of the application.
func main() {
	flag.Parse()
	ctx := context.Background()
	ax, err := openAX206(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer ax.Close()
	if *info {
		fmt.Printf("Detected resolution: %dx%d\n", ax.width, ax.height)
		return
	}
	var src string
	if *htmlFile != "" {
		absPath, err := filepath.Abs(*htmlFile)
		if err != nil {
			log.Fatal(err)
		}
		src = "file://" + absPath
	} else {
		fmt.Println("Usage:")
		fmt.Println(" --html file.html Render a local HTML file")
		fmt.Println(" --loop Run in infinite loop")
		fmt.Println(" --interval=1000ms Interval between renderings in loop mode")
		fmt.Println(" --format=brg565 Color format (rgb565, bgr565, brg565)")
		fmt.Println(" --endian=little Endianness (little or big)")
		fmt.Println(" --verbose Enable verbose logging")
		fmt.Println(" --rotate=90 Image Rotation (0, 90, 180, 270)")
		fmt.Println(" --info Show only display resolution")
		return
	}
	startSystemInfoServer()
	for {
		img, err := renderSource(src, ax.width, ax.height)
		if err != nil {
			log.Fatal(err)
		}
		img = rotateImage(img, *rotate)
		buf := convertToBuffer(img, ax.width, ax.height, *format, *endian)
		if err := ax.blit(buf, 0, 0, ax.width, ax.height, 0x12); err != nil {
			log.Fatal(err)
		}
		if *verbose {
			log.Printf("Source %s rendered and sent (%s, %s-endian, rotate=%d).", src, *format, *endian, *rotate)
		}
		if !*loop {
			break
		}
		time.Sleep(*interval)
	}
}
