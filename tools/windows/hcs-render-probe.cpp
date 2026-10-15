// Standalone guest-only Direct3D probe. Native C++ is used for the COM graphics
// ABI; the Go host executable remains cgo-free. No network or CI integration.
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <cstdio>
#include <cwchar>

template<class T> struct Owned {
 T* p = nullptr;
 ~Owned() { if (p) p->Release(); }
 T** out() { return &p; }
 T* operator->() const { return p; }
};
struct Result {
 bool desktop=false, hardware=false, presented=false, pixels=false;
 unsigned stage=0, vendor=0, device=0;
 HRESULT hr=S_OK;
};
static LRESULT CALLBACK WindowProc(HWND w,UINT m,WPARAM a,LPARAM b) {
 return DefWindowProcW(w,m,a,b);
}
static void run(Result& r) {
 r.stage=1;
 DWORD session=0;
 HDESK input=OpenInputDesktop(0,FALSE,DESKTOP_READOBJECTS);
 if (!input) return;
 wchar_t name[128]={}; DWORD used=0;
 bool inputDefault=GetUserObjectInformationW(input,UOI_NAME,name,sizeof(name),&used) && _wcsicmp(name,L"Default")==0;
 CloseDesktop(input);
 if (!inputDefault || !ProcessIdToSessionId(GetCurrentProcessId(),&session) || !session || session!=WTSGetActiveConsoleSessionId()) return;
 if (!GetUserObjectInformationW(GetThreadDesktop(GetCurrentThreadId()),UOI_NAME,name,sizeof(name),&used) || _wcsicmp(name,L"Default")!=0) return;
 r.desktop=true;
 r.stage=2;
 WNDCLASSW wc={};wc.lpfnWndProc=WindowProc;wc.hInstance=GetModuleHandleW(nullptr);wc.lpszClassName=L"BivouacHcsRenderProbe";
 if (!RegisterClassW(&wc)) return;
 HWND window=CreateWindowW(wc.lpszClassName,L"Disposable HCS rendering validation",WS_OVERLAPPEDWINDOW|WS_VISIBLE,80,80,384,256,nullptr,nullptr,wc.hInstance,nullptr);
 if (!window) return;
 struct CloseWindow {HWND h; ~CloseWindow(){DestroyWindow(h);}} closeWindow{window};
 ShowWindow(window,SW_SHOW);SetWindowPos(window,HWND_TOPMOST,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_SHOWWINDOW);UpdateWindow(window);
 DXGI_SWAP_CHAIN_DESC desc={};desc.BufferDesc.Width=256;desc.BufferDesc.Height=128;desc.BufferDesc.Format=DXGI_FORMAT_R8G8B8A8_UNORM;
 desc.SampleDesc.Count=1;desc.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;desc.BufferCount=1;desc.OutputWindow=window;desc.Windowed=TRUE;desc.SwapEffect=DXGI_SWAP_EFFECT_DISCARD;
 Owned<IDXGISwapChain> swap;Owned<ID3D11Device> device;Owned<ID3D11DeviceContext> context;
 D3D_FEATURE_LEVEL level={};const D3D_FEATURE_LEVEL levels[]={D3D_FEATURE_LEVEL_11_0};
 r.stage=3;
 r.hr=D3D11CreateDeviceAndSwapChain(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,0,levels,1,D3D11_SDK_VERSION,&desc,swap.out(),device.out(),&level,context.out());
 if (FAILED(r.hr)) return;
 Owned<IDXGIDevice> dxgi;Owned<IDXGIAdapter> adapter;DXGI_ADAPTER_DESC ad={};
 r.hr=device->QueryInterface(__uuidof(IDXGIDevice),reinterpret_cast<void**>(dxgi.out()));if(FAILED(r.hr))return;
 r.hr=dxgi->GetAdapter(adapter.out());if(FAILED(r.hr))return;
 r.hr=adapter->GetDesc(&ad);if(FAILED(r.hr))return;
 // Microsoft Basic Render Driver is WARP. Never accept it as hardware.
 if (ad.VendorId==0x1414 && ad.DeviceId==0x008c) return;
 Owned<IDXGIAdapter1> adapter1;DXGI_ADAPTER_DESC1 ad1={};
 r.hr=adapter->QueryInterface(__uuidof(IDXGIAdapter1),reinterpret_cast<void**>(adapter1.out()));if(FAILED(r.hr))return;
 r.hr=adapter1->GetDesc1(&ad1);if(FAILED(r.hr) || (ad1.Flags&DXGI_ADAPTER_FLAG_SOFTWARE))return;
 r.vendor=ad.VendorId;r.device=ad.DeviceId;r.hardware=true;
 Owned<ID3D11Texture2D> back,staging;Owned<ID3D11RenderTargetView> view;
 r.stage=4;
 r.hr=swap->GetBuffer(0,__uuidof(ID3D11Texture2D),reinterpret_cast<void**>(back.out()));if(FAILED(r.hr))return;
 r.hr=device->CreateRenderTargetView(back.p,nullptr,view.out());if(FAILED(r.hr))return;
 D3D11_TEXTURE2D_DESC td={};back->GetDesc(&td);td.Usage=D3D11_USAGE_STAGING;td.BindFlags=0;td.CPUAccessFlags=D3D11_CPU_ACCESS_READ;td.MiscFlags=0;
 r.hr=device->CreateTexture2D(&td,nullptr,staging.out());if(FAILED(r.hr))return;
 for(unsigned color=0;color<2;color++) {
  const float rgba[2][4]={{1,0,0,1},{0,1,0,1}};
  context->ClearRenderTargetView(view.p,rgba[color]);
  context->CopyResource(staging.p,back.p);
  D3D11_MAPPED_SUBRESOURCE mapped={};
  r.stage=5;
  r.hr=context->Map(staging.p,0,D3D11_MAP_READ,0,&mapped);if(FAILED(r.hr))return;
  const unsigned char* pixel=static_cast<const unsigned char*>(mapped.pData)+64*mapped.RowPitch+128*4;
  bool matches=pixel[0]==(color==0?255:0) && pixel[1]==(color==1?255:0) && pixel[2]==0 && pixel[3]==255;
  context->Unmap(staging.p,0);if(!matches)return;
  r.stage=6;
  for(unsigned frame=0;frame<15;frame++) {
   MSG msg;while(PeekMessageW(&msg,nullptr,0,0,PM_REMOVE)){TranslateMessage(&msg);DispatchMessageW(&msg);}
   context->ClearRenderTargetView(view.p,rgba[color]);
   r.hr=swap->Present(1,0);if(r.hr!=S_OK)return;
   Sleep(16);
  }
  r.stage=8;
  RECT client={};if(!GetClientRect(window,&client))return;
  POINT point={(client.right-client.left)/2,(client.bottom-client.top)/2};
  if(!ClientToScreen(window,&point))return;
  HDC screen=GetDC(nullptr);if(!screen)return;
  COLORREF desktopPixel=GetPixel(screen,point.x,point.y);ReleaseDC(nullptr,screen);
  if(desktopPixel!=RGB(color==0?255:0,color==1?255:0,0))return;
 }
 r.pixels=true;r.presented=true;r.stage=7;
}
int main() {
 Result r;run(r);
 char json[512];
 int count=std::snprintf(json,sizeof(json),"{\"desktop_ready\":%s,\"hardware_d3d11\":%s,\"presented\":%s,\"pixel_readback\":%s,\"stage\":%u,\"hresult\":%u,\"vendor_id\":%u,\"device_id\":%u}",r.desktop?"true":"false",r.hardware?"true":"false",r.presented?"true":"false",r.pixels?"true":"false",r.stage,static_cast<unsigned>(r.hr),r.vendor,r.device);
 HANDLE file=CreateFileW(L"C:\\ProgramData\\BivouacHcsSpike\\render.json",GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(file==INVALID_HANDLE_VALUE)return 2;
 DWORD written=0;bool saved=WriteFile(file,json,count,&written,nullptr)&&written==static_cast<DWORD>(count);FlushFileBuffers(file);CloseHandle(file);
 return saved && r.desktop && r.hardware && r.presented && r.pixels ? 0 : 1;
}
