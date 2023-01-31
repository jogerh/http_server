#include "http_server.h"
#include <strsafe.h>
#include <winrt/base.h>

void InitializeResponse(HTTP_RESPONSE* resp, USHORT status, PCSTR reason) {
	RtlZeroMemory((resp), sizeof(*(resp)));
	resp->StatusCode = (status);
	resp->pReason = (reason);
	resp->ReasonLength = static_cast<USHORT>(strlen(reason));
}

void AddHeader(HTTP_RESPONSE& Response, DWORD HeaderId, PCSTR RawValue) {
	Response.Headers.KnownHeaders[HeaderId].pRawValue = RawValue;
	Response.Headers.KnownHeaders[HeaderId].RawValueLength = static_cast<USHORT>(strlen(RawValue));
}

/***************************************************************************++
Routine Description:
	The routine to receive a request. This routine calls the corresponding
	routine to deal with the response.
Arguments:
	hReqQueue - Handle to the request queue.
Return Value:
	Success/Failure.
--***************************************************************************/
DWORD RequestQueue::ReceiveRequests(char* wwwAuthValue) const
{
	//
	// Allocate a 2K buffer. Should be good for most requests, we'll grow
	// this if required. We also need space for a HTTP_REQUEST structure.
	//

	ULONG bufferSize = sizeof(HTTP_REQUEST) + 2048;
	std::vector<CHAR> requestBuffer(bufferSize);


	//
	// Wait for a new request -- This is indicated by a NULL request ID.
	//
	HTTP_REQUEST_ID requestId;
	HTTP_SET_NULL_ID(&requestId);

	int i = 0;

	DWORD result;
	for (;;)
	{
		fill(begin(requestBuffer), end(requestBuffer), 0);

		DWORD bytesRead{};
		auto request = reinterpret_cast<PHTTP_REQUEST>(requestBuffer.data());

		result = HttpReceiveHttpRequest(
			m_queue.Get(), // Req Queue
			requestId, // Req ID
			0, // Flags
			request, // HTTP request buffer
			bufferSize, // req buffer length
			&bytesRead, // bytes received
			nullptr // LPOVERLAPPED
		);

		if (NO_ERROR == result)
		{
			//
			// Worked!
			//
			switch (request->Verb)
			{
			case HttpVerbGET:
				wprintf(L"Got a GET request for %ws \n", request->CookedUrl.pFullUrl);

				if (request->pRequestInfo &&
					request->pRequestInfo->InfoType == HttpRequestInfoTypeAuth &&
					static_cast<HTTP_REQUEST_AUTH_INFO*>(request->pRequestInfo->pInfo)->AuthStatus ==
					HttpAuthStatusSuccess)
				{
					wprintf(L"Request is authenticated, sending 200\n");
					result = SendHttpResponse(request, 200, wwwAuthValue, "OK", "Hey! You hit the server \r\n");
				}
				else
				{
					wprintf(L"Request is not authenticated, sending 401\n");
					result = SendHttpResponse(request, 401, nullptr, "Unauthorized", "Gimme Negotiate \r\n");
				}

				break;

			default:
				wprintf(L"Got a unknown request for %ws \n", request->CookedUrl.pFullUrl);

				result = SendHttpResponse(request, 503, nullptr, "Not Implemented", nullptr);
				break;
			}

			if (result != NO_ERROR)
			{
				break;
			}

			//
			// Reset the Request ID so that we pick up the next request.
			//
			HTTP_SET_NULL_ID(&requestId);
		}
		else if (result == ERROR_MORE_DATA)
		{
			//
			// The input buffer was too small to hold the request headers
			// We have to allocate more buffer & call the API again.
			//
			// When we call the API again, we want to pick up the request
			// that just failed. This is done by passing a RequestID.
			//
			// This RequestID is picked from the old buffer.
			//
			requestId = request->RequestId;

			//
			// Free the old buffer and allocate a new one.
			//
			bufferSize = bytesRead;
			requestBuffer.resize(bufferSize);

			request = reinterpret_cast<PHTTP_REQUEST>(requestBuffer.data());
		}
		else if (ERROR_CONNECTION_INVALID == result &&
			!HTTP_IS_NULL_ID(&requestId))
		{
			// The TCP connection got torn down by the peer when we were
			// trying to pick up a request with more buffer. We'll just move
			// onto the next request.

			HTTP_SET_NULL_ID(&requestId);
		}
		else
		{
			break;
		}
	} // for(;;)


	return result;
}

RequestQueue::RequestQueue(RequestQueueHandle queue) : m_queue{ std::move(queue) }
{
}

const RequestQueueHandle& RequestQueue::Handle() const
{
	return m_queue;
}

UrlGroup::UrlGroup(UrlGroupHandle urlGroup) : m_urlGroup{ std::move(urlGroup) }
{
}

void UrlGroup::AddUrl(const wchar_t* url)
{
	check_win32(HttpAddUrlToUrlGroup(m_urlGroup.Get(), url, 0, 0));
}

void UrlGroup::Bind(const RequestQueue& queue)
{
	HTTP_BINDING_INFO BindingProperty;
	BindingProperty.Flags.Present = 1; // Specifies that the property is present on UrlGroup
	BindingProperty.RequestQueueHandle = queue.Handle().Get();
	SetProperty(HttpServerBindingProperty, &BindingProperty);
}

void UrlGroup::SetTimeout(int timeout)
{
	HTTP_TIMEOUT_LIMIT_INFO CGTimeout{};
	CGTimeout.Flags.Present = 1; // Specifies that the property is present on UrlGroup
	CGTimeout.EntityBody = timeout;   //The timeout is in secs

	SetProperty(HttpServerTimeoutsProperty, &CGTimeout);
}

template <typename T>
void UrlGroup::SetProperty(HTTP_SERVER_PROPERTY property, T* value)
{
	check_win32(HttpSetUrlGroupProperty(m_urlGroup.Get(), property, value, sizeof(T)));
}

Session::Session(SessionHandle session) : m_session{ std::move(session) }
{
}

UrlGroup Session::CreateUrlGroup() const
{
	UrlGroupHandle urlGroup;
	check_win32(HttpCreateUrlGroup(m_session.Get(), urlGroup.GetAddressOf(), 0));
	return urlGroup;
}

void Session::EnableAuthNegotiation()
{
	HTTP_SERVER_AUTHENTICATION_INFO AuthInfo{};
	AuthInfo.Flags.Present = 1;
	AuthInfo.AuthSchemes = HTTP_AUTH_ENABLE_NEGOTIATE;

	SetProperty(HttpServerAuthenticationProperty, &AuthInfo);
}

template <typename T>
void Session::SetProperty(HTTP_SERVER_PROPERTY prop, T* info)
{
	check_win32(HttpSetServerSessionProperty(m_session.Get(), prop, info, sizeof(T)));
}

HttpApi::HttpApi()
{
	check_win32(HttpInitialize(
		m_apiVersion,
		HTTP_INITIALIZE_SERVER, // Flags
		nullptr // Reserved
	));
}

Session HttpApi::CreateSession() const
{
	SessionHandle session;
	check_win32(HttpCreateServerSession(m_apiVersion, session.GetAddressOf(), 0));
	return session;
}

RequestQueue HttpApi::CreateRequestQueue(const std::wstring& name) const
{
	RequestQueueHandle queue;
	check_win32(HttpCreateRequestQueue(m_apiVersion,
		name.c_str(),
		nullptr,
		0,
		queue.GetAddressOf()));
	return queue;
}

HttpApi::~HttpApi()
{
	HttpTerminate(HTTP_INITIALIZE_SERVER, nullptr);
}

DWORD RequestQueue::SendHttpResponse(
	PHTTP_REQUEST pRequest,
	USHORT StatusCode,
	char* wwwAuthValue,
	PSTR pReason,
	PSTR pEntityString
) const
{
	//
	// Initialize the HTTP response structure.
	//
	HTTP_RESPONSE response;
	InitializeResponse(&response, StatusCode, pReason);

	if (StatusCode == 401)
		AddHeader(response, HttpHeaderWwwAuthenticate, "Negotiate");

	if (StatusCode == 200 && wwwAuthValue)
		AddHeader(response, HttpHeaderWwwAuthenticate, wwwAuthValue);

	//
	// Add a known header.
	//
	AddHeader(response, HttpHeaderContentType, "text/html");

	HTTP_DATA_CHUNK dataChunk;
	if (pEntityString)
	{
		//
		// Add an entity chunk
		//
		dataChunk.DataChunkType = HttpDataChunkFromMemory;
		dataChunk.FromMemory.pBuffer = pEntityString;
		dataChunk.FromMemory.BufferLength = static_cast<ULONG>(strlen(pEntityString));

		response.EntityChunkCount = 1;
		response.pEntityChunks = &dataChunk;
	}

	//
	// Since we are sending all the entity body in one call, we don't have
	// to specify the Content-Length.
	//

	DWORD bytesSent;
	auto result = HttpSendHttpResponse(
		m_queue.Get(), // ReqQueueHandle
		pRequest->RequestId, // Request ID
		0, // Flags
		&response, // HTTP response
		nullptr, // pReserved1
		&bytesSent, // bytes sent   (OPTIONAL)
		nullptr, // pReserved2   (must be NULL)
		0, // Reserved3    (must be 0)
		nullptr, // LPOVERLAPPED (OPTIONAL)
		nullptr // pReserved4   (must be NULL)
	);

	if (result != NO_ERROR)
	{
		wprintf(L"HttpSendHttpResponse failed with %lu \n", result);
	}

	return result;
}

/***************************************************************************++
Routine Description:
	The routine sends a HTTP response after reading the entity body.
Arguments:
	hReqQueue     - Handle to the request queue.
	pRequest      - The parsed HTTP request.
Return Value:
	Success/Failure.
--***************************************************************************/
DWORD RequestQueue::SendHttpPostResponse(PHTTP_REQUEST pRequest) const
{
	DWORD result;
	DWORD bytesSent;
	ULONG EntityBufferLength;
	ULONG BytesRead;
	ULONG TempFileBytesWritten;
	HANDLE hTempFile;
	TCHAR szTempName[MAX_PATH + 1];
#define MAX_ULONG_STR ((ULONG) sizeof("4294967295"))
	CHAR szContentLength[MAX_ULONG_STR];
	HTTP_DATA_CHUNK dataChunk;
	ULONG TotalBytesRead = 0;

	BytesRead = 0;
	hTempFile = INVALID_HANDLE_VALUE;

	//
	// Allocate some space for an entity buffer. We'll grow this on demand.
	//
	EntityBufferLength = 2048;
	std::vector<PUCHAR> pEntityBuffer(EntityBufferLength);


	//
	// Initialize the HTTP response structure.
	//
	HTTP_RESPONSE response;
	InitializeResponse(&response, 200, "OK");

	//
	// For POST, we'll echo back the entity that we got from the client.
	//
	// NOTE: If we had passed the HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY
	//       flag with HttpReceiveHttpRequest(), the entity would have
	//       been a part of HTTP_REQUEST (using the pEntityChunks field).
	//       Since we have not passed that flag, we can be assured that
	//       there are no entity bodies in HTTP_REQUEST.
	//

	if (pRequest->Flags & HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS)
	{
		// The entity body is send over multiple calls. Let's collect all
		// of these in a file & send it back. We'll create a temp file
		//

		if (GetTempFileName(
			L".",
			L"New",
			0,
			szTempName
		) == 0)
		{
			result = GetLastError();
			wprintf(L"GetTempFileName failed with %lu \n", result);
			goto Done;
		}

		hTempFile = CreateFile(
			szTempName,
			GENERIC_READ | GENERIC_WRITE,
			0, // don't share.
			nullptr, // no security descriptor
			CREATE_ALWAYS, // overrwrite existing
			FILE_ATTRIBUTE_NORMAL, // normal file.
			nullptr
		);

		if (hTempFile == INVALID_HANDLE_VALUE)
		{
			result = GetLastError();
			wprintf(L"Could not create temporary file. Error %lu \n", result);
			goto Done;
		}

		do
		{
			//
			// Read the entity chunk from the request.
			//
			BytesRead = 0;
			result = HttpReceiveRequestEntityBody(
				m_queue.Get(),
				pRequest->RequestId,
				0,
				pEntityBuffer.data(),
				EntityBufferLength,
				&BytesRead,
				nullptr
			);

			switch (result)
			{
			case NO_ERROR:

				if (BytesRead != 0)
				{
					TotalBytesRead += BytesRead;
					WriteFile(
						hTempFile,
						pEntityBuffer.data(),
						BytesRead,
						&TempFileBytesWritten,
						nullptr
					);
				}
				break;

			case ERROR_HANDLE_EOF:

				//
				// We have read the last request entity body. We can send
				// back a response.
				//
				// To illustrate entity sends via
				// HttpSendResponseEntityBody, we will send the response
				// over multiple calls. This is achieved by passing the
				// HTTP_SEND_RESPONSE_FLAG_MORE_DATA flag.

				if (BytesRead != 0)
				{
					TotalBytesRead += BytesRead;
					WriteFile(
						hTempFile,
						pEntityBuffer.data(),
						BytesRead,
						&TempFileBytesWritten,
						nullptr
					);
				}

				//
				// Since we are sending the response over multiple API
				// calls, we have to add a content-length.
				//
				// Alternatively, we could have sent using chunked transfer
				// encoding, by passing "Transfer-Encoding: Chunked".
				//

				// NOTE: Since we are accumulating the TotalBytesRead in
				//       a ULONG, this will not work for entity bodies that
				//       are larger than 4 GB. For supporting large entity
				//       bodies, we would have to use a ULONGLONG.
				//


				StringCchPrintfA(
					szContentLength,
					sizeof(szContentLength),
					"%lu",
					TotalBytesRead
				);

				AddHeader(
					response,
					HttpHeaderContentLength,
					szContentLength
				);

				result =
					HttpSendHttpResponse(
						m_queue.Get(), // ReqQueueHandle
						pRequest->RequestId, // Request ID
						HTTP_SEND_RESPONSE_FLAG_MORE_DATA,
						&response, // HTTP response
						nullptr, // pReserved1
						&bytesSent, // bytes sent (optional)
						nullptr, // pReserved2
						0, // Reserved3
						nullptr, // LPOVERLAPPED
						nullptr // pReserved4
					);

				if (result != NO_ERROR)
				{
					wprintf(L"HttpSendHttpResponse failed with %lu \n",
						result);
					goto Done;
				}

				//
				// Send entity body from a file handle.
				//
				dataChunk.DataChunkType =
					HttpDataChunkFromFileHandle;

				dataChunk.FromFileHandle.
					ByteRange.StartingOffset.QuadPart = 0;

				dataChunk.FromFileHandle.
					ByteRange.Length.QuadPart = HTTP_BYTE_RANGE_TO_EOF;

				dataChunk.FromFileHandle.FileHandle = hTempFile;

				result = HttpSendResponseEntityBody(
					m_queue.Get(),
					pRequest->RequestId,
					0, // This is the last send.
					1, // Entity Chunk Count.
					&dataChunk,
					nullptr,
					nullptr,
					0,
					nullptr,
					nullptr
				);

				if (result != NO_ERROR)
				{
					wprintf(
						L"HttpSendResponseEntityBody failed with %lu \n",
						result
					);
				}

				goto Done;

				break;


			default:
				wprintf(L"HttpReceiveRequestEntityBody failed with %lu \n",
					result);
				goto Done;
			}
		} while (TRUE);
	}
	// This request does not have any entity body.
	//

	result = HttpSendHttpResponse(
		m_queue.Get(), // ReqQueueHandle
		pRequest->RequestId, // Request ID
		0,
		&response, // HTTP response
		nullptr, // pReserved1
		&bytesSent, // bytes sent (optional)
		nullptr, // pReserved2
		0, // Reserved3
		nullptr, // LPOVERLAPPED
		nullptr // pReserved4
	);
	if (result != NO_ERROR)
	{
		wprintf(L"HttpSendHttpResponse failed with %lu \n", result);
	}

Done:


	if (INVALID_HANDLE_VALUE != hTempFile)
	{
		CloseHandle(hTempFile);
		DeleteFile(szTempName);
	}

	return result;
}
