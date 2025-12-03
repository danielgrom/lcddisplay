package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/png"
	"log"
	"os"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/google/gousb"
)

const (
	vid      = 0x1908
	pid      = 0x0102
	endptOut = 0x01
	endptIn  = 0x81
)

var (
	htmlFile = flag.String("html", "", "Render a local HTML file")
	urlFlag  = flag.String("url", "", "Render an external URL")
	loop     = flag.Bool("loop", false, "Run in infinite loop")
	info     = flag.Bool("info", false, "Show display information")
	format   = flag.String("format", "brg565", "Color format: rgb565, bgr565, brg565")
	endian   = flag.String("endian", "little", "Endianness: little or big")
	interval = flag.Duration("interval", time.Second, "Interval between renderings in loop mode (e.g., 200ms, 1s)")
)

type ax206 struct {
	dev    *gousb.Device
	cfg    *gousb.Config
	intf   *gousb.Interface
	outEP  *gousb.OutEndpoint
	inEP   *gousb.InEndpoint
	width  int
	height int
}

func openAX206(ctx context.Context) (*ax206, error) {
	usbCtx := gousb.NewContext()
	dev, err := usbCtx.OpenDeviceWithVIDPID(vid, pid)
	if err != nil {
		return nil, fmt.Errorf("open device: %w", err)
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
		return fmt.Errorf("bad ACK")
	}
	if ack[12] != 0x00 {
		return fmt.Errorf("status %02x", ack[12])
	}
	return nil
}

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

// conversion of pixel to 16 bits per color format
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

func renderSource(src string, w, h int) (image.Image, error) {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	var pngBuf []byte
	if err := chromedp.Run(ctx,
		chromedp.Navigate(src),
		chromedp.EmulateViewport(int64(w), int64(h)),
		chromedp.FullScreenshot(&pngBuf, 100),
	); err != nil {
		return nil, err
	}
	return png.Decode(bytes.NewReader(pngBuf))
}

func main() {
	flag.Parse()

	ctx := context.Background()
	ax, err := openAX206(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer ax.Close()

	// Show only display info
	if *info {
		fmt.Printf("Detected resolution: %dx%d\n", ax.width, ax.height)
		return
	}

	// Determine source (HTML file or external URL)
	var src string
	if *urlFlag != "" {
		src = *urlFlag
	} else if *htmlFile != "" {
		htmlBytes, err := os.ReadFile(*htmlFile)
		if err != nil {
			log.Fatal(err)
		}
		src = "data:text/html," + string(htmlBytes)
	} else {
		fmt.Println("Usage:")
		fmt.Println("  --html file.html       Render a local HTML file")
		fmt.Println("  --url https://site     Render an external URL")
		fmt.Println("  --loop                 Run in infinite loop")
		fmt.Println("  --interval=200ms       Interval between renderings in loop mode")
		fmt.Println("  --format=brg565        Color format (rgb565, bgr565, brg565)")
		fmt.Println("  --endian=little        Endianness (little or big)")
		fmt.Println("  --info                 Show display information")
		return
	}

	// Rendering loop
	for {
		img, err := renderSource(src, ax.width, ax.height)
		if err != nil {
			log.Fatal(err)
		}
		buf := convertToBuffer(img, ax.width, ax.height, *format, *endian)
		if err := ax.blit(buf, 0, 0, ax.width, ax.height, 0x12); err != nil {
			log.Fatal(err)
		}
		log.Printf("Source %s rendered and sent (%s, %s-endian).", src, *format, *endian)

		if !*loop {
			break
		}
		time.Sleep(*interval)
	}
}
