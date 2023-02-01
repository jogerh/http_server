#pragma once
#include "http_handle.h"

class RequestQueue
{
public:
	RequestQueue(RequestQueueHandle queue);
	const RequestQueueHandle& Handle() const;
	DWORD ReceiveRequests(char* www_auth_val) const;

private:

	DWORD SendHttpResponse(
		PHTTP_REQUEST request,
		USHORT statusCode,
		char* wwwAuthValue,
		PSTR reasonText,
		PSTR pEntity
	) const;

	DWORD SendHttpPostResponse(PHTTP_REQUEST pRequest) const;
	RequestQueueHandle m_queue;
};

class UrlGroup
{
public:
	UrlGroup(UrlGroupHandle urlGroup);

	void AddUrl(const wchar_t* url);
	void Bind(const RequestQueue& queue);
	void SetTimeout(int timeout);

private:
	template <typename T>
	void SetProperty(HTTP_SERVER_PROPERTY property, T* value);

	UrlGroupHandle m_urlGroup;
};


class Session
{
public:
	Session(SessionHandle session);

	UrlGroup CreateUrlGroup() const;
	void EnableAuthNegotiation();

private:
	template <typename T>
	void SetProperty(HTTP_SERVER_PROPERTY prop, T* info);

	SessionHandle m_session;
};


class HttpApi
{
public:

	HttpApi();
	~HttpApi();

	Session CreateSession() const;
	RequestQueue CreateRequestQueue(const std::wstring& name) const;

private:
	const HTTPAPI_VERSION m_apiVersion = HTTPAPI_VERSION_2;

};

struct HttpResponse
{
	HttpResponse(unsigned short status, const char* reason) {
		m_response.StatusCode = status;
		m_response.pReason = reason;
		m_response.ReasonLength = static_cast<unsigned short>(strlen(reason));
	}

	void AddHeader(unsigned long HeaderId, const char* rawValue) {
		m_response.Headers.KnownHeaders[HeaderId].pRawValue = rawValue;
		m_response.Headers.KnownHeaders[HeaderId].RawValueLength = static_cast<unsigned short>(strlen(rawValue));
	}

	HTTP_RESPONSE* Get()
	{
		return &m_response;
	}

	void AddContent(const char* content)
	{
		if (content)
		{
			m_content.push_back(content);
			{
				HTTP_DATA_CHUNK chunk;

				chunk.DataChunkType = HttpDataChunkFromMemory;
				chunk.FromMemory.pBuffer = const_cast<char*>(m_content.back().c_str());
				chunk.FromMemory.BufferLength = static_cast<ULONG>(strlen(content));

				m_chunks.push_back(chunk);
			}
			m_response.EntityChunkCount = static_cast<unsigned short>(m_chunks.size());
			m_response.pEntityChunks = m_chunks.data();
		}

	}

private:
	HTTP_RESPONSE m_response{};
	std::vector<HTTP_DATA_CHUNK> m_chunks;
	std::vector<std::string> m_content;
};