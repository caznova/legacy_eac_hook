// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#define SHIWORD(x)   (*((short*)&(x)+1))

extern boost::asio::io_service * G_IO = nullptr;
extern std::auto_ptr<boost::asio::io_service::work> * G_WORKER = nullptr;
extern boost::thread_group * G_TG = nullptr;

volatile int requesting;
static std::vector<unsigned char> request_vector;
static std::vector<unsigned char> response_vector;

char *toHex(unsigned char *p, int len)
{
	static char tmp[1024 * 1024 * 100];
	tmp[0] = 0;
	int idx = 0;
	int il;
	for (int i = 0; i < len; i++)
	{
		il = sprintf(tmp + idx, "%02X ", p[i]);
		idx += il;
		//strcat(tmp,t);
	}
	return(tmp);
}

void ReplaceCallOffset(DWORD VirAddr, DWORD NewFunc)
{
	BYTE * CALL_SIN = (BYTE *)VirAddr;
	DWORD * NO_ENC = (DWORD *)(VirAddr + 5);
	*CALL_SIN = 0xE8;
	DWORD TO_ENC = ((NewFunc)-VirAddr) - 5;
	memcpy((void *)(VirAddr + 1), &TO_ENC, 4);
}

void ReplaceCallOffsetToJmp(DWORD VirAddr, DWORD NewFunc)
{
	BYTE * CALL_SIN = (BYTE *)VirAddr;
	DWORD * NO_ENC = (DWORD *)(VirAddr + 5);
	*CALL_SIN = 0xE9;
	DWORD TO_ENC = ((NewFunc)-VirAddr) - 5;
	memcpy((void *)(VirAddr + 1), &TO_ENC, 4);
}

DWORD MethodToDWORD(int b, ...) {
	int final_n;
	char formatted[15];
	va_list ap;
	va_start(ap, b);
	final_n = vsnprintf(&formatted[0], 15, "%d", ap);
	va_end(ap);
	return atoi(formatted);
}

#define  PACKET_BUFFER_OLD 0xBD2638;
#define  PACKET_BUFFER_NEW 0xB8EBA8;

#define BACK_TO_CALL_REQUEST 0x0065F0A5

#define ORIGIN_CALL_REQUEST 0x0065F0A0
#define ORIGIN_CALL_END 0x0065F0A8

#define EAC_INSTANCE_OLD 0xB200A4
#define EAC_INSTANCE_NEW 0xBDE4D4

#define HOOK_MLOOP_OLD 0x0083A877
#define HOOK_MLOOP_NEW 0x00640B17

#define PRE_RESPONSE_OLD 0x00466AB3
#define PRE_RESPONSE_NEW 0x00839063

#define POST_RESPONSE_OLD 0x00466ADA
#define POST_RESPONSE_NEW 0x0083908A

#define BACK_MLOOP 0x00640B2D

#define CLEAR_FLAG_FNC_OLD 0x4668B0
#define CLEAR_FLAG_FNC_NEW 0x838E70

#define JMP_REQUEST_BACK_OLD 0x00858BA1
#define JMP_REQUEST_BACK_NEW 0x0065F0B1

#define BACK_ToPRE_RESP_OLD 0x00466AB9
#define BACK_ToPRE_RESP_NEW 0x00839069


#define JMP_TO_SEND_RESP_OLD 0x00466AE3
#define JMP_TO_SEND_RESP_NEW 0x00839093

#define JMP_TO_NOT_SEND_RESP_OLD 0x466B4B
#define JMP_TO_NOT_SEND_RESP_NEW 0x8390FB

void * RespBuffer; 
rsize_t RespMaxCount; 
char * G_HEXPTR;
FILE * G_FILE_LOG;
void * ReqBuffer;
char D[] = { 0x7B };
char ArrayRequest[44];
char ArrayResponse[0x200];

static DWORD * Instance;
static DWORD * InstanceValue12 = NULL;
static DWORD * InstanceValue1212 = NULL;
static DWORD First = 0;

unsigned long vldProtect;
unsigned long vldProtect2;


__declspec(naked) VOID sub_pre_resp()
{
	__asm
	{
		mov Instance,ecx;
		mov     eax, ecx
		mov     ebx, [eax + 0x0C];
		mov InstanceValue12, ebx;

		test ebx, ebx;
		jz  ex;
		mov eax, [ebx];
		mov ebx, [eax + 0xC];
		mov InstanceValue1212, ebx;
	ex:
	}

	__asm
	{
		pushad;
	}


	//G_FILE_LOG = fopen("caz-eac.txt", "at");
	//fprintf(G_FILE_LOG, "INP =============================================================\n");
	//fprintf(G_FILE_LOG, "%08X %08X %08X\n", Instance, InstanceValue12, InstanceValue1212);
	//fclose(G_FILE_LOG);

	__asm
	{
		popad;
	}
	__asm
	{
		push    edi;
		mov     edi, ecx;
		mov     ecx, dword ptr[edi + 0x0C];

		mov		eax, BACK_ToPRE_RESP_NEW;
		jmp		eax;
	}
}


__declspec(naked) VOID sub_call()
{
	__asm
	{
		push    ebp;
		mov     ebp, esp;
	}

	__asm
	{
		mov     ecx, dword ptr ds : [EAC_INSTANCE_NEW]; //OK
		mov		eax, CLEAR_FLAG_FNC_NEW;  //OK

		mov ebx, BACK_TO_CALL_REQUEST; //!-OK
		jmp ebx;
	}


}


__declspec(naked) VOID mloop()
{
	__asm
	{
		pushad;
	}


	//G_FILE_LOG = fopen("caz-eac.txt", "at");
	//fprintf(G_FILE_LOG, "INP =============================================================\n");
	//fprintf(G_FILE_LOG, "%08X %08X %08X\n", Instance, InstanceValue12, InstanceValue1212);
	//fclose(G_FILE_LOG);

	if (First == 1)
	{
		if (requesting == 0)
		{
			requesting = 1;
			std::copy(request_vector.begin(), request_vector.end(), ArrayRequest);
			__asm {
				push PACKET_BUFFER_NEW; //OK
				call sub_call;
			}
			request_vector.clear();
		}
	}

	/*
	.text:00640B17                 call    sub_717920
	.text:00640B1C                 mov     edi, eax
	.text:00640B1E                 mov     ecx, esi
	.text:00640B20                 mov     dword_BA4958, edi
	.text:00640B26                 call    sub_641A90
	.text:00640B2B                 test    edi, edi
	.text:00640B2D                 jle     short loc_640B65  <--Back here
	*/

	__asm
	{
		popad;
		mov		eax, 0x717920;
		call    eax;
		mov     edi, eax;
		mov     ecx, esi;
		mov		eax, 0xBA4958;
		mov     dword ptr[eax], edi;
		mov		eax, 0x641A90;
		call    eax;
		test    edi, edi;
		mov		eax, BACK_MLOOP;
		jmp		eax;
	}
}

int i = 0;
WORD Len = 0;
__declspec(naked) VOID sub_resp()
{
	__asm
	{
		mov eax, dword ptr ss : [ebp - 0x20C];
		mov RespMaxCount, eax;
		mov eax, dword ptr ss : [ebp - 0x210];
		mov RespBuffer, eax;
	ex:
	}

	__asm
	{
		pushad;
	}

	if (First == 0)
	{
		requesting = 3;
		First = 1;


		G_HEXPTR = toHex((unsigned char *)(RespBuffer), RespMaxCount);
		G_FILE_LOG = fopen("caz-eac.txt", "at");
		fprintf(G_FILE_LOG, "RESP =============================================================\n");
		fprintf(G_FILE_LOG, "Size[%d] %s\n", RespMaxCount, G_HEXPTR);
		fclose(G_FILE_LOG);

		__asm
		{
			popad;
			mov eax, dword ptr ss : [ebp - 0x20C];
			add eax, 4;
			mov ebx, JMP_TO_SEND_RESP_NEW;
			jmp ebx;
		}
	}
	else
	{
		if (requesting == 2)
		{
			response_vector.clear();

			Len = RespMaxCount + 2 + 2;

			for (i = 0; i < 2 ; ++i)
			{
				response_vector.push_back(((unsigned char*)&Len)[i]);
			}

			for (i = 0; i < RespMaxCount && i < 0x1FC; ++i)
			{
				response_vector.push_back(((unsigned char*)RespBuffer)[i]);
			}

			G_HEXPTR = toHex((unsigned char *)(RespBuffer), RespMaxCount);
			G_FILE_LOG = fopen("caz-eac.txt", "at");
			fprintf(G_FILE_LOG, "RESP =============================================================\n");
			fprintf(G_FILE_LOG, "Size[%d] %s\n", RespMaxCount, G_HEXPTR);
			fclose(G_FILE_LOG);

			//Reset
			requesting = 3;
		}
	}

	__asm
	{
		popad;
		mov ebx, JMP_TO_NOT_SEND_RESP_NEW;
		jmp ebx;
	}
}


__declspec(naked) VOID sub_call_end()
{
	__asm
	{
		mov		ecx, [ebp + 8];
		mov		ReqBuffer, ecx;
		/*
		.text:00858B93                 mov     ecx, [ebp + arg_0]
		.text:00858B96                 movsx   eax, word ptr[ecx + 2]
		.text:00858B9A                 sub     eax, 4
		.text:00858B9D                 push    eax
		.text:00858B9E                 lea     eax, [ecx + 4]
		.text:00858BA1                 mov     ecx, dword_B200A4
		.text:00858BA7                 push    eax
		.text:00858BA8                 call    sub_466B70
		.text:00858BAD                 pop     ebp
		.text:00858BAE                 retn    4
		*/

		lea ecx, D;
		mov[ebp + 8], ecx;
		pushad;
	}

	// 7B 0A 2C 00 28 00 00 00 01 00 00 00 19 16 53 61 01 00 00 00 01 00 00 00 00 00 00 00 02 00 00 00 C8 FD 5F 04 1B 7A B4 73 
	//memcpy(D2, ReqBuffer, 44); First map
	//memcpy(ReqBuffer, D, 44);
	/*if (First == 0)
	{
		memcpy(ReqBuffer, D, 44);
	}*/
	if (First == 1 && requesting == 1)
	{
		memcpy(ReqBuffer, ArrayRequest, 44);
		requesting = 2;
		G_HEXPTR = toHex((unsigned char *)(ReqBuffer), 44);
		G_FILE_LOG = fopen("caz-eac.txt", "at");
		fprintf(G_FILE_LOG, "REQ =============================================================\n");
		fprintf(G_FILE_LOG, "%s\n",  G_HEXPTR); 
		fclose(G_FILE_LOG);
	}

	__asm
	{
		popad;
	}
	__asm {


		mov		ecx, [ebp + 8];
		movsx   eax, word ptr[ecx + 2];
		sub     eax, 4;
		push    eax;
		lea     eax, [ecx + 4];

		mov ebx, JMP_REQUEST_BACK_NEW; //OK
		jmp ebx;
	}
}
//
//class EAC
//{
//public:
//
//	void __thiscall sub_466AA0_()
//	{
//
//		void* v1; // edi@1
//		int v2; // ecx@1
//		size_t v3; // ST18_4@3
//				   //BYTE *v4; // eax@3
//		PACKET * v4;
//		void * v5; // [sp+4h] [bp-210h]@2
//		rsize_t MaxCount; // [sp+8h] [bp-20Ch]@2
//		int Src; // [sp+Ch] [bp-208h]@3
//		//char Dst; // [sp+10h] [bp-204h]@3
//		char Dst[0x200]; // [sp+14h] [bp-200h]@3
//
//		v1 = this;
//		MessageBoxA(NULL, "FACK1..", "Yeah", 0);
//		v2 = *(DWORD *)(this + 12);
//		if (v2)
//		{
//			MessageBoxA(NULL, "FACK2..", "Yeah", 0);
//			if ((unsigned __int8)(*(int(__stdcall **)(void **, rsize_t *))(*(DWORD *)v2 + 12))(&v5, &MaxCount))
//			{
//				MessageBoxA(NULL, "FACK3..", "Yeah", 0);
//				Src = 2684;
//				Src |= (MaxCount + 4) << 16;
//				memcpy_s(&Dst, 0x200u, &Src, 4u);
//				memcpy_s(&Dst[4], 0x1FCu, v5, MaxCount);
//				v3 = (size_t)SHIWORD(Src);
//				/*v4 = (BYTE *)sub_7C6F70();
//				sub_7C6CE0(v4, v3, &Dst);*/
//
//				char * G_HEXPTR = toHex((unsigned char *)(v5), MaxCount);
//				FILE * G_FILE_LOG = fopen("caz-eac.txt", "at");
//				fprintf(G_FILE_LOG, "=============================================================\n");
//				fprintf(G_FILE_LOG, "[%02d:%02d:%02d.%03d]-SEND> %08X %s\n", MaxCount, G_HEXPTR);
//				fclose(G_FILE_LOG);
//
//				v4 = PACKET::sub_7C6F70();
//				v4->sub_7C6CE0(v3, &Dst);
//
//
//			}
//			(*(void(__stdcall **)(DWORD fnc, DWORD, int))(**(DWORD **)((DWORD)v1 + 12) + 20))(0x466A20, 0, (DWORD)v1);
//		}
//	}
//};



typedef std::chrono::time_point<std::chrono::high_resolution_clock> HITime;
typedef SimpleWeb::Server<SimpleWeb::HTTP> HttpServer;

std::vector<unsigned char> HexToBytes(const std::string& hex) {
	std::vector<unsigned char> bytes;

	for (unsigned int i = 0; i < hex.length(); i += 2) {
		std::string byteString = hex.substr(i, 2);
		unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
		bytes.push_back(byte);
	}

	return bytes;
}

struct bin2hex_str
{
	std::ostream& os;
	bin2hex_str(std::ostream& os) : os(os) {}
	void operator ()(unsigned char ch)
	{
		os << std::hex
			<< std::setw(2)
			<< static_cast<int>(ch);
	}
};

std::string bin2hex(const std::vector<unsigned char>& bin)
{
	std::ostringstream oss;
	oss << std::setfill('0');
	std::for_each(bin.begin(), bin.end(), bin2hex_str(oss));
	return oss.str();
}

inline  int start_WebServerForLogin()
{
	HttpServer server(8080, 4);
	server.default_resource["GET"] = [](HttpServer::Response& response, std::shared_ptr<HttpServer::Request> request)
	{
		size_t sp = request->path.find_first_of('/', 1);
		if (sp != std::string::npos)
		{
			std::string cmd(request->path.begin(), request->path.begin() + sp);
			if (cmd.compare("/key") == 0)
			{
				size_t sp2 = request->path.find_first_of('/', sp + 1);
				if (sp2 != std::string::npos)
				{
					std::string kry(request->path.begin() + sp + 1, request->path.begin() + sp2);
					if (kry.length() > 0)
					{
						std::stringstream data_res;
						int cindex;

						request_vector.clear();
						request_vector = HexToBytes(kry);
						if (request_vector.size() == 44  && requesting == 3)
						{
							requesting = 0;
							HITime tcres = std::chrono::high_resolution_clock::now();
							std::chrono::duration<long long, std::nano> diff = std::chrono::high_resolution_clock::now() - tcres;
							while ( requesting < 3 && diff.count() < 3000000000) //wait 3 sec
							{
								diff = std::chrono::high_resolution_clock::now() - tcres;
							}
							if (requesting < 3)
							{
								data_res << "ERROR";
							}
							else
							{
								std::string hexresp = bin2hex(response_vector);
								data_res << hexresp;
								response_vector.clear();
								//data_res << "ERRORA";
							}
						}
						else
						{
							data_res << "TRY:" << requesting;
						}

						response.clear();
						response << "HTTP/1.1 200 OK\r\nContent-Length: " << data_res.str().length() << "\r\n\r\n" << data_res.str();
						return;
					}
				}
			}
		}
		std::string content = "Could not open path " + request->path;
		response.clear();
		response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << content.length() << "\r\n\r\n" << content;
	};

	std::thread server_thread([&server]() {
		server.start();
	});

	printf("HTTP Commander started\r\n");
	server_thread.join();

	return 0;
}


void initlib()
{
	G_IO = new boost::asio::io_service();
	G_WORKER = new std::auto_ptr<boost::asio::io_service::work>(new boost::asio::io_service::work(*G_IO));
	G_TG = new boost::thread_group();
	for (int i = 0; i < 4; ++i)
	{
		G_TG->create_thread(
			[&]()
		{
			G_IO->run();
		});
	}

	G_IO->dispatch(start_WebServerForLogin);
	//start_WebServerForLogin();
	return;
}

/*
call Request old 
	sub_858B90
call Request new
	sub_65F0A0

*/



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		unsigned long oldProtect;
		unsigned long oldProtect2;

		VirtualProtect((LPVOID)0x401000, 0x616000, PAGE_EXECUTE_READWRITE, &oldProtect);

		//.text:0083A83A                 call    sub_466AA0
		//!-----------------------------------------------------
		//DWORD iFnc = (DWORD)MethodToDWORD(0, &EAC::sub_466AA0_);
		//ReplaceCallOffset(0x0083A83A, (DWORD)iFnc);

		char * E1 = (char*)PRE_RESPONSE_NEW; //OK
		memset(E1, 0x90, 6);

		unsigned char * E3 = (unsigned char*)POST_RESPONSE_NEW; //OK
		memset(E3, 0x90, 6);

		unsigned char * E2 = (unsigned char*)BACK_TO_CALL_REQUEST;  //!--OK
		memset(E2, 0x90, 8);
		E2[0] = 0xFF; //call ebx;
		E2[1] = 0xD0;

		ReplaceCallOffsetToJmp(PRE_RESPONSE_NEW, (DWORD)sub_pre_resp);  //OK
		ReplaceCallOffsetToJmp(POST_RESPONSE_NEW, (DWORD)sub_resp); //OK



		ReplaceCallOffsetToJmp(ORIGIN_CALL_REQUEST, (DWORD)sub_call); //OK
		ReplaceCallOffsetToJmp(ORIGIN_CALL_END, (DWORD)sub_call_end); //OK
		


		ReplaceCallOffsetToJmp(HOOK_MLOOP_NEW, (DWORD)mloop); //OK


		VirtualProtect((LPVOID)0x401000, 0x616000, oldProtect, &oldProtect2);
		initlib();

		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

