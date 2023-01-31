#pragma once
#include "http_handle.h"

class RequestQueue
{
public:
	RequestQueue(RequestQueueHandle queue);
	const RequestQueueHandle& Handle() const;
	void ReceiveRequests(char* www_auth_val) const;

private:

	DWORD SendHttpResponse(
		PHTTP_REQUEST pRequest,
		USHORT StatusCode,
		char* wwwAuthValue,
		PSTR pReason,
		PSTR pEntity
	) const;

	DWORD SendHttpPostResponse(PHTTP_REQUEST pRequest) const;
	DWORD DoReceiveRequests(char* wwwAuthVal) const;
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
