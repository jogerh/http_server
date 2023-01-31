#pragma once

#define SECURITY_WIN32

#include <http.h>
#include <Windows.h>
#include <sspi.h>
#include <strsafe.h>
#include <vector>
#include <winrt/base.h>
#include "http_handle.h"

class RequestQueue
{
public:
	RequestQueue(RequestQueueHandle queue)
		: m_queue{ std::move(queue) }
	{
	}

	const RequestQueueHandle& Handle() const
	{
		return m_queue;
	}

	void ReceiveRequests(char* www_auth_val) const
	{
		DoReceiveRequests(www_auth_val);
	}


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
	UrlGroup(UrlGroupHandle urlGroup) : m_urlGroup{ std::move(urlGroup) }
	{
	}

	void AddUrl(const wchar_t* url)
	{
		check_win32(HttpAddUrlToUrlGroup(m_urlGroup.Get(), url, 0, 0));
	}

	void Bind(const RequestQueue& queue)
	{
		HTTP_BINDING_INFO BindingProperty;
		BindingProperty.Flags.Present = 1; // Specifies that the property is present on UrlGroup
		BindingProperty.RequestQueueHandle = queue.Handle().Get();
		SetProperty(HttpServerBindingProperty, &BindingProperty);
	}

	void SetTimeout(int timeout)
	{
		HTTP_TIMEOUT_LIMIT_INFO CGTimeout{};
		CGTimeout.Flags.Present = 1; // Specifies that the property is present on UrlGroup
		CGTimeout.EntityBody = timeout;   //The timeout is in secs

		SetProperty(HttpServerTimeoutsProperty, &CGTimeout);
	}

private:

	template <typename T>
	void SetProperty(HTTP_SERVER_PROPERTY property, T* value)
	{
		check_win32(HttpSetUrlGroupProperty(m_urlGroup.Get(), property, value, sizeof(T)));
	}

	UrlGroupHandle m_urlGroup;
};


class Session
{
public:
	Session(SessionHandle session) : m_session{ std::move(session) }
	{
	}

	UrlGroup CreateUrlGroup() const
	{
		UrlGroupHandle urlGroup;
		check_win32(HttpCreateUrlGroup(m_session.Get(), urlGroup.GetAddressOf(), 0));
		return urlGroup;
	}

	void EnableAuthNegotiation()
	{
		HTTP_SERVER_AUTHENTICATION_INFO AuthInfo{};
		AuthInfo.Flags.Present = 1;
		AuthInfo.AuthSchemes = HTTP_AUTH_ENABLE_NEGOTIATE;

		SetProperty(HttpServerAuthenticationProperty, &AuthInfo);
	}

private:
	template <typename T>
	void SetProperty(HTTP_SERVER_PROPERTY prop, T* info)
	{
		check_win32(HttpSetServerSessionProperty(m_session.Get(), prop, info, sizeof(T)));
	}

	SessionHandle m_session;
};


class HttpApi
{
public:

	HttpApi()
	{
		check_win32(HttpInitialize(
			m_apiVersion,
			HTTP_INITIALIZE_SERVER, // Flags
			nullptr // Reserved
		));
	}

	Session CreateSession() const
	{
		SessionHandle session;
		check_win32(HttpCreateServerSession(m_apiVersion, session.GetAddressOf(), 0));
		return session;
	}

	RequestQueue CreateRequestQueue(const std::wstring& name) const
	{
		RequestQueueHandle queue;
		check_win32(HttpCreateRequestQueue(m_apiVersion,
			name.c_str(),
			nullptr,
			0,
			queue.GetAddressOf()));
		return queue;
	}

	~HttpApi()
	{
		HttpTerminate(HTTP_INITIALIZE_SERVER, nullptr);
	}

private:
	const HTTPAPI_VERSION m_apiVersion = HTTPAPI_VERSION_2;

};
