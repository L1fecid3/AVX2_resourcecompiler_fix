package main

import (
    "bytes"
    "fmt"
    "os"
    "path/filepath"
    "runtime"
    "syscall"
    "unsafe"
)

const (
    WM_DESTROY = 0x0002
    WM_COMMAND = 0x0111
    WM_SETFONT = 0x0030

    WS_OVERLAPPED  = 0x00000000
    WS_CAPTION     = 0x00C00000
    WS_SYSMENU     = 0x00080000
    WS_MINIMIZEBOX = 0x00020000
    WS_VISIBLE     = 0x10000000
    WS_CHILD       = 0x40000000
    WS_TABSTOP     = 0x00010000

    BS_PUSHBUTTON = 0x00000000
    SS_LEFT       = 0x00000000

    CW_USEDEFAULT int32 = -2147483648
    SW_SHOW             = 5
    COLOR_WINDOW        = 5

    ID_SELECT = 1001
    ID_PATCH  = 1002
    ID_PATH   = 1003
    ID_STATUS = 1004

    MB_OK              = 0x00000000
    MB_ICONERROR       = 0x00000010
    MB_ICONINFORMATION = 0x00000040

    COINIT_APARTMENTTHREADED = 0x2
    CLSCTX_INPROC_SERVER     = 0x1

    FOS_PICKFOLDERS     = 0x00000020
    FOS_FORCEFILESYSTEM = 0x00000040
    FOS_PATHMUSTEXIST   = 0x00000800

    SIGDN_FILESYSPATH = 0x80058000
    HRESULT_CANCELLED = 0x800704C7
)

type POINT struct{ X, Y int32 }
type MSG struct {
    Hwnd    syscall.Handle
    Message uint32
    WParam  uintptr
    LParam  uintptr
    Time    uint32
    Pt      POINT
}
type WNDCLASSEX struct {
    CbSize        uint32
    Style         uint32
    LpfnWndProc   uintptr
    CbClsExtra    int32
    CbWndExtra    int32
    HInstance     syscall.Handle
    HIcon         syscall.Handle
    HCursor       syscall.Handle
    HbrBackground syscall.Handle
    LpszMenuName  *uint16
    LpszClassName *uint16
    HIconSm       syscall.Handle
}
type GUID struct {
    Data1 uint32
    Data2 uint16
    Data3 uint16
    Data4 [8]byte
}
type comObject struct {
    vtbl *uintptr
}

var (
    user32   = syscall.NewLazyDLL("user32.dll")
    kernel32 = syscall.NewLazyDLL("kernel32.dll")
    gdi32    = syscall.NewLazyDLL("gdi32.dll")
    ole32    = syscall.NewLazyDLL("ole32.dll")

    procRegisterClassExW = user32.NewProc("RegisterClassExW")
    procCreateWindowExW  = user32.NewProc("CreateWindowExW")
    procDefWindowProcW   = user32.NewProc("DefWindowProcW")
    procShowWindow       = user32.NewProc("ShowWindow")
    procUpdateWindow     = user32.NewProc("UpdateWindow")
    procGetMessageW      = user32.NewProc("GetMessageW")
    procTranslateMessage = user32.NewProc("TranslateMessage")
    procDispatchMessageW = user32.NewProc("DispatchMessageW")
    procPostQuitMessage  = user32.NewProc("PostQuitMessage")
    procSetWindowTextW   = user32.NewProc("SetWindowTextW")
    procMessageBoxW      = user32.NewProc("MessageBoxW")
    procSendMessageW     = user32.NewProc("SendMessageW")
    procLoadCursorW      = user32.NewProc("LoadCursorW")
    procEnableWindow     = user32.NewProc("EnableWindow")

    procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
    procGetStockObject   = gdi32.NewProc("GetStockObject")

    procCoInitializeEx   = ole32.NewProc("CoInitializeEx")
    procCoUninitialize   = ole32.NewProc("CoUninitialize")
    procCoCreateInstance = ole32.NewProc("CoCreateInstance")
    procCoTaskMemFree    = ole32.NewProc("CoTaskMemFree")

    hwndSelect syscall.Handle
    hwndPatch  syscall.Handle
    hwndPath   syscall.Handle
    hwndStatus syscall.Handle

    selectedRoot string
)

var (
    CLSID_FileOpenDialog = GUID{0xDC1C5A9C, 0xE88A, 0x4DDE, [8]byte{0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7}}
    IID_IFileOpenDialog  = GUID{0xD57C7288, 0xD4AD, 0x4768, [8]byte{0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60}}
)

func utf16Ptr(s string) *uint16 {
    p, _ := syscall.UTF16PtrFromString(s)
    return p
}

func setText(hwnd syscall.Handle, s string) {
    procSetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(utf16Ptr(s))))
}

func messageBox(hwnd syscall.Handle, title, text string, flags uintptr) {
    procMessageBoxW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(utf16Ptr(text))), uintptr(unsafe.Pointer(utf16Ptr(title))), flags)
}

func enableWindow(hwnd syscall.Handle, enabled bool) {
    v := uintptr(0)
    if enabled { v = 1 }
    procEnableWindow.Call(uintptr(hwnd), v)
}

func createWindowEx(exStyle uint32, class, title string, style uint32, x, y, w, h int32, parent syscall.Handle, menu uintptr, instance syscall.Handle) syscall.Handle {
    r, _, _ := procCreateWindowExW.Call(
        uintptr(exStyle),
        uintptr(unsafe.Pointer(utf16Ptr(class))),
        uintptr(unsafe.Pointer(utf16Ptr(title))),
        uintptr(style),
        uintptr(x), uintptr(y), uintptr(w), uintptr(h),
        uintptr(parent), menu, uintptr(instance), 0,
    )
    return syscall.Handle(r)
}

func loword(v uintptr) uint16 { return uint16(v & 0xffff) }
func hresultFailed(hr uintptr) bool { return int32(uint32(hr)) < 0 }

func comCall(obj *comObject, index int, args ...uintptr) uintptr {
    vt := unsafe.Slice(obj.vtbl, 32)
    all := make([]uintptr, 0, len(args)+1)
    all = append(all, uintptr(unsafe.Pointer(obj)))
    all = append(all, args...)
    r, _, _ := syscall.SyscallN(vt[index], all...)
    return r
}

func comRelease(obj *comObject) {
    if obj != nil { comCall(obj, 2) }
}

func chooseGameRoot(owner syscall.Handle) (string, bool, error) {
    var dlg *comObject
    hr, _, _ := procCoCreateInstance.Call(
        uintptr(unsafe.Pointer(&CLSID_FileOpenDialog)),
        0,
        CLSCTX_INPROC_SERVER,
        uintptr(unsafe.Pointer(&IID_IFileOpenDialog)),
        uintptr(unsafe.Pointer(&dlg)),
    )
    if hresultFailed(hr) || dlg == nil {
        return "", false, fmt.Errorf("Could not open the Windows folder picker (HRESULT 0x%08X)", uint32(hr))
    }
    defer comRelease(dlg)

    var opts uint32
    hr = comCall(dlg, 10, uintptr(unsafe.Pointer(&opts))) // GetOptions
    if hresultFailed(hr) {
        return "", false, fmt.Errorf("Could not read folder picker options (HRESULT 0x%08X)", uint32(hr))
    }
    opts |= FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST
    hr = comCall(dlg, 9, uintptr(opts)) // SetOptions
    if hresultFailed(hr) {
        return "", false, fmt.Errorf("Could not configure folder picker (HRESULT 0x%08X)", uint32(hr))
    }

    title := utf16Ptr("Select the Counter-Strike Global Offensive folder")
    _ = comCall(dlg, 17, uintptr(unsafe.Pointer(title))) // SetTitle

    hr = comCall(dlg, 3, uintptr(owner)) // Show
    if uint32(hr) == HRESULT_CANCELLED {
        return "", false, nil
    }
    if hresultFailed(hr) {
        return "", false, fmt.Errorf("Folder picker failed (HRESULT 0x%08X)", uint32(hr))
    }

    var item *comObject
    hr = comCall(dlg, 20, uintptr(unsafe.Pointer(&item))) // GetResult
    if hresultFailed(hr) || item == nil {
        return "", false, fmt.Errorf("Could not get the selected folder (HRESULT 0x%08X)", uint32(hr))
    }
    defer comRelease(item)

    var pathPtr *uint16
    hr = comCall(item, 5, SIGDN_FILESYSPATH, uintptr(unsafe.Pointer(&pathPtr))) // IShellItem::GetDisplayName
    if hresultFailed(hr) || pathPtr == nil {
        return "", false, fmt.Errorf("Could not resolve the selected folder path (HRESULT 0x%08X)", uint32(hr))
    }
    defer procCoTaskMemFree.Call(uintptr(unsafe.Pointer(pathPtr)))

    path := syscall.UTF16ToString(unsafe.Slice(pathPtr, 32768))
    return filepath.Clean(path), true, nil
}

func validateRoot(root string) (string, error) {
    if root == "" {
        return "", fmt.Errorf("Select the Counter-Strike Global Offensive folder first.")
    }
    dllPath := filepath.Join(root, "game", "bin", "win64", "resourcecompiler.dll")
    info, err := os.Stat(dllPath)
    if err != nil || info.IsDir() {
        return dllPath, fmt.Errorf("resourcecompiler.dll was not found.\r\n\r\nExpected:\r\n%s", dllPath)
    }
    return dllPath, nil
}

func wndProc(hwnd syscall.Handle, msg uint32, wParam, lParam uintptr) uintptr {
    switch msg {
    case WM_COMMAND:
        switch loword(wParam) {
        case ID_SELECT:
            root, ok, err := chooseGameRoot(hwnd)
            if err != nil {
                messageBox(hwnd, "CS2 AVX2 Workaround", err.Error(), MB_OK|MB_ICONERROR)
                return 0
            }
            if !ok { return 0 }

            selectedRoot = root
            setText(hwndPath, root)
            dllPath, err := validateRoot(root)
            if err != nil {
                setText(hwndStatus, "Selected folder does not contain the expected CS2 Workshop Tools file.")
                enableWindow(hwndPatch, false)
                messageBox(hwnd, "CS2 AVX2 Workaround", err.Error(), MB_OK|MB_ICONERROR)
                return 0
            }
            setText(hwndStatus, "Target: "+dllPath)
            enableWindow(hwndPatch, true)
            return 0

        case ID_PATCH:
            dllPath, err := validateRoot(selectedRoot)
            if err != nil {
                messageBox(hwnd, "CS2 AVX2 Workaround", err.Error(), MB_OK|MB_ICONERROR)
                enableWindow(hwndPatch, false)
                return 0
            }

            enableWindow(hwndSelect, false)
            enableWindow(hwndPatch, false)
            setText(hwndStatus, "Patching resourcecompiler.dll...")

            result, err := patchDLL(dllPath)

            enableWindow(hwndSelect, true)
            enableWindow(hwndPatch, true)
            if err != nil {
                setText(hwndStatus, "Patch failed. No unsupported changes were applied.")
                messageBox(hwnd, "CS2 AVX2 Workaround", err.Error()+"\r\n\r\nFile:\r\n"+dllPath, MB_OK|MB_ICONERROR)
                return 0
            }
            setText(hwndStatus, result)
            messageBox(hwnd, "CS2 AVX2 Workaround", result+"\r\n\r\nFile:\r\n"+dllPath, MB_OK|MB_ICONINFORMATION)
            return 0
        }

    case WM_DESTROY:
        procPostQuitMessage.Call(0)
        return 0
    }
    r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
    return r
}

type sigPattern struct {
    bytes     []byte
    mask      string
    branchPos int
}

var sig1 = sigPattern{
    bytes: []byte{
        0x83,0x3D,0,0,0,0,0x32,0x4C,0x8D,0x8C,0x24,0x80,0,0,0,0x89,0x54,0x24,0x20,0x45,0x8B,0xC4,0x8B,0xD0,0x49,0x8B,0xCA,0,0x07,0xE8,0,0,0,0,0xEB,0x05,0xE8,0,0,0,0,
    },
    mask: "xx????xxxxxxxxxxxxxxxxxxxxx?xx????xxx????",
    branchPos: 27,
}

var sig2 = sigPattern{
    bytes: []byte{
        0xF2,0x0F,0x11,0x0D,0,0,0,0,0,0x0B,0x48,0x8D,0x05,0,0,0,0,0x48,0x89,0x43,0x38,0xFF,0x13,0x85,0xC0,0x74,0x40,
    },
    mask: "xxxx?????xxxx????xxxxxxxxxx",
    branchPos: 8,
}

func matchAt(data []byte, pos int, p sigPattern) bool {
    if pos < 0 || pos+len(p.bytes) > len(data) { return false }
    for i := range p.bytes {
        if p.mask[i] == 'x' && data[pos+i] != p.bytes[i] { return false }
    }
    return true
}

func findSignature(data []byte, p sigPattern) []int {
    out := []int{}
    first := -1
    for i := range p.mask {
        if p.mask[i] == 'x' { first = i; break }
    }
    if first < 0 { return out }
    needle := []byte{p.bytes[first]}
    base := 0
    for base < len(data) {
        idx := bytes.Index(data[base:], needle)
        if idx < 0 { break }
        absolute := base + idx - first
        if matchAt(data, absolute, p) { out = append(out, absolute) }
        base += idx + 1
    }
    return out
}

func patchDLL(path string) (string, error) {
    data, err := os.ReadFile(path)
    if err != nil { return "", fmt.Errorf("Could not read resourcecompiler.dll: %v", err) }
    if len(data) < 2 || data[0] != 'M' || data[1] != 'Z' {
        return "", fmt.Errorf("The target file is not a valid Windows DLL.")
    }

    m1 := findSignature(data, sig1)
    m2 := findSignature(data, sig2)
    if len(m1) != 1 || len(m2) != 1 {
        return "", fmt.Errorf("Unsupported resourcecompiler.dll build.\r\nThe expected AVX2 dispatch signatures were not found exactly once.\r\nNothing was changed.")
    }

    p1 := m1[0] + sig1.branchPos
    p2 := m2[0] + sig2.branchPos
    b1, b2 := data[p1], data[p2]

    valid := func(b byte) bool { return b == 0x7C || b == 0xEB }
    if !valid(b1) || !valid(b2) {
        return "", fmt.Errorf("Unsupported branch bytes found. Nothing was changed.")
    }
    if b1 == 0xEB && b2 == 0xEB {
        return "Already patched. No changes were needed.", nil
    }

    backup := path + ".bak"
    if _, err := os.Stat(backup); os.IsNotExist(err) {
        if err := os.WriteFile(backup, data, 0644); err != nil {
            return "", fmt.Errorf("Could not create backup:\r\n%s\r\n\r\n%v", backup, err)
        }
    }

    original := append([]byte(nil), data...)

    f, err := os.OpenFile(path, os.O_WRONLY, 0)
    if err != nil {
        return "", fmt.Errorf("Could not open resourcecompiler.dll for writing.\r\nClose CS2 Workshop Tools and try running this utility as Administrator.\r\n\r\n%v", err)
    }
    _, err1 := f.WriteAt([]byte{0xEB}, int64(p1))
    _, err2 := f.WriteAt([]byte{0xEB}, int64(p2))
    syncErr := f.Sync()
    closeErr := f.Close()
    if err1 != nil || err2 != nil || syncErr != nil || closeErr != nil {
        _ = os.WriteFile(path, original, 0644)
        return "", fmt.Errorf("Patch write failed; original file was restored.")
    }

    verify, err := os.ReadFile(path)
    if err != nil || verify[p1] != 0xEB || verify[p2] != 0xEB {
        _ = os.WriteFile(path, original, 0644)
        return "", fmt.Errorf("Patch verification failed; original file was restored.")
    }

    return fmt.Sprintf("Patch successful. Backup created: %s", filepath.Base(backup)), nil
}

func main() {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()

    hr, _, _ := procCoInitializeEx.Call(0, COINIT_APARTMENTTHREADED)
    if !hresultFailed(hr) {
        defer procCoUninitialize.Call()
    }

    hInst, _, _ := procGetModuleHandleW.Call(0)
    className := "CS2AVX2WorkaroundWindowV5"

    cursor, _, _ := procLoadCursorW.Call(0, 32512)
    wc := WNDCLASSEX{
        CbSize:        uint32(unsafe.Sizeof(WNDCLASSEX{})),
        LpfnWndProc:   syscall.NewCallback(wndProc),
        HInstance:     syscall.Handle(hInst),
        HCursor:       syscall.Handle(cursor),
        HbrBackground: syscall.Handle(COLOR_WINDOW + 1),
        LpszClassName: utf16Ptr(className),
    }
    if r, _, _ := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 { return }

    hwnd := createWindowEx(0, className, "CS2 Workshop Tools AVX2 Workaround",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX|WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 760, 320, 0, 0, syscall.Handle(hInst))
    if hwnd == 0 { return }

    font, _, _ := procGetStockObject.Call(17)

    intro := createWindowEx(0, "STATIC",
        "Select the root Counter-Strike Global Offensive folder.\r\nThe utility will patch game\\bin\\win64\\resourcecompiler.dll and create a .bak backup.",
        WS_CHILD|WS_VISIBLE|SS_LEFT,
        24, 20, 700, 50, hwnd, 0, syscall.Handle(hInst))
    procSendMessageW.Call(uintptr(intro), WM_SETFONT, font, 1)

    hwndSelect = createWindowEx(0, "BUTTON", "Select Folder...",
        WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,
        24, 88, 170, 38, hwnd, ID_SELECT, syscall.Handle(hInst))
    procSendMessageW.Call(uintptr(hwndSelect), WM_SETFONT, font, 1)

    hwndPatch = createWindowEx(0, "BUTTON", "Patch",
        WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,
        208, 88, 120, 38, hwnd, ID_PATCH, syscall.Handle(hInst))
    procSendMessageW.Call(uintptr(hwndPatch), WM_SETFONT, font, 1)
    enableWindow(hwndPatch, false)

    pathLabel := createWindowEx(0, "STATIC", "Selected folder:",
        WS_CHILD|WS_VISIBLE|SS_LEFT,
        24, 146, 140, 24, hwnd, 0, syscall.Handle(hInst))
    procSendMessageW.Call(uintptr(pathLabel), WM_SETFONT, font, 1)

    hwndPath = createWindowEx(0, "STATIC", "Not selected",
        WS_CHILD|WS_VISIBLE|SS_LEFT,
        24, 172, 700, 36, hwnd, ID_PATH, syscall.Handle(hInst))
    procSendMessageW.Call(uintptr(hwndPath), WM_SETFONT, font, 1)

    hwndStatus = createWindowEx(0, "STATIC", "",
        WS_CHILD|WS_VISIBLE|SS_LEFT,
        24, 224, 700, 42, hwnd, ID_STATUS, syscall.Handle(hInst))
    procSendMessageW.Call(uintptr(hwndStatus), WM_SETFONT, font, 1)

    procShowWindow.Call(uintptr(hwnd), SW_SHOW)
    procUpdateWindow.Call(uintptr(hwnd))

    var msg MSG
    for {
        r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
        if int32(r) <= 0 { break }
        procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
        procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
    }
}
