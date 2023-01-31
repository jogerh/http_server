#include "http_server.h"

void INITIALIZE_HTTP_RESPONSE(HTTP_RESPONSE* resp, USHORT status, PSTR reason) {
	RtlZeroMemory((resp), sizeof(*(resp)));
	resp->StatusCode = (status);
	resp->pReason = (reason);
	resp->ReasonLength = static_cast<USHORT>(strlen(reason));
}

void ADD_KNOWN_HEADER(HTTP_RESPONSE& Response, DWORD HeaderId, PSTR RawValue) {
	Response.Headers.KnownHeaders[(HeaderId)].pRawValue = (RawValue);
	Response.Headers.KnownHeaders[(HeaderId)].RawValueLength = static_cast<USHORT>(strlen(RawValue));
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
DWORD RequestQueue::DoReceiveRequests(char* wwwAuthValue) const
{
	ULONG result;
	HTTP_REQUEST_ID requestId;
	DWORD bytesRead;

	//
	// Allocate a 2K buffer. Should be good for most requests, we'll grow
	// this if required. We also need space for a HTTP_REQUEST structure.
	//

	ULONG RequestBufferLength = sizeof(HTTP_REQUEST) + 2048;
	std::vector<PCHAR> pRequestBuffer(RequestBufferLength);

	auto pRequest = reinterpret_cast<PHTTP_REQUEST>(pRequestBuffer.data());

	//
	// Wait for a new request -- This is indicated by a NULL request ID.
	//

	HTTP_SET_NULL_ID(&requestId);

	int i = 0;

	for (;;)
	{
		RtlZeroMemory(pRequest, RequestBufferLength);

		result = HttpReceiveHttpRequest(
			m_queue.Get(), // Req Queue
			requestId, // Req ID
			0, // Flags
			pRequest, // HTTP request buffer
			RequestBufferLength, // req buffer length
			&bytesRead, // bytes received
			nullptr // LPOVERLAPPED
		);

		if (NO_ERROR == result)
		{
			//
			// Worked!
			//
			switch (pRequest->Verb)
			{
			case HttpVerbGET:
				wprintf(L"Got a GET request for %ws \n", pRequest->CookedUrl.pFullUrl);

				if (pRequest->pRequestInfo &&
					pRequest->pRequestInfo->InfoType == HttpRequestInfoTypeAuth &&
					static_cast<HTTP_REQUEST_AUTH_INFO*>(pRequest->pRequestInfo->pInfo)->AuthStatus ==
					HttpAuthStatusSuccess)
				{
					wprintf(L"Request is authenticated, sending 200\n");
					result = SendHttpResponse(
						pRequest,
						200,
						wwwAuthValue,
						"OK",
						"Hey! You hit the server \r\n"
					);
				}
				else
				{
					wprintf(L"Request is not authenticated, sending 401\n");
					result = SendHttpResponse(
						pRequest,
						401,
						nullptr,
						"Unauthorized",
						"Gimme Negotiate \r\n"
					);
				}

				break;

			default:
				wprintf(L"Got a unknown request for %ws \n",
					pRequest->CookedUrl.pFullUrl);

				result = SendHttpResponse(
					pRequest,
					503,
					nullptr,
					"Not Implemented",
					nullptr
				);
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
			requestId = pRequest->RequestId;

			//
			// Free the old buffer and allocate a new one.
			//
			RequestBufferLength = bytesRead;
			pRequestBuffer.resize(RequestBufferLength);

			pRequest = reinterpret_cast<PHTTP_REQUEST>(pRequestBuffer.data());
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

/***************************************************************************++
Routine Description:
	The routine sends a HTTP response.
Arguments:
	hReqQueue     - Handle to the request queue.
	pRequest      - The parsed HTTP request.
	StatusCode    - Response Status Code.
	pReason       - Response reason phrase.
	pEntityString - Response entity body.
Return Value:
	Success/Failure.
--***************************************************************************/
DWORD RequestQueue::SendHttpResponse(
	IN PHTTP_REQUEST pRequest,
	IN USHORT StatusCode,
	IN char* wwwAuthValue,
	__in IN PSTR pReason,
	__in_opt IN PSTR pEntityString
) const
{
	HTTP_RESPONSE response;
	HTTP_DATA_CHUNK dataChunk;
	DWORD result;
	DWORD bytesSent;

	//
	// Initialize the HTTP response structure.
	//
	INITIALIZE_HTTP_RESPONSE(&response, StatusCode, pReason);

	if (StatusCode == 401)
		ADD_KNOWN_HEADER(response, HttpHeaderWwwAuthenticate, "Negotiate");

	if (StatusCode == 200 && wwwAuthValue)
		ADD_KNOWN_HEADER(response, HttpHeaderWwwAuthenticate, wwwAuthValue);

	//
	// Add a known header.
	//
	ADD_KNOWN_HEADER(response, HttpHeaderContentType, "text/html");

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

	result = HttpSendHttpResponse(
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
	HTTP_RESPONSE response;
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
	INITIALIZE_HTTP_RESPONSE(&response, 200, "OK");

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

				ADD_KNOWN_HEADER(
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
