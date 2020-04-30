Servicekonto Integration für Liferay
====================================

Diese Module repräsentieren eine mögliche Integration des deutschen Servicekontos in Liferay.

In der OpenID Connect Standardimplementierung von Liferay 7.1.3 GA4 fehlt die Behandlung von JWT-kodierten Antworten
auf die user-info Abfrage. Da einige Implementierungen des Servicekontos die Antworten in JWT liefern, führt ein Aufruf
zu einer NullPointerException in der Behandlungsroutine von Liferay.

Diese Module fügen eine Behandlung von JWT Antworten hinzu. Außerdem werden zusätzliche Daten übernommen wie der
mittlere Name und der Geburtstag.

Installation
------------

Nach dem Deployment der Module müssen die im Modul `servicekonto-openid-connect-service-handler` abgelegten Dateien nach `liferay.home/osgi/configs` kopiert werden:

* `com.liferay.login.authentication.openid.connect.web.internal.portlet.action.OpenIdConnectLoginRequestMVCActionCommand.config`
* `com.liferay.login.authentication.openid.connect.web.internal.portlet.action.OpenIdConnectLoginResponseMVCActionCommand.config`
* `com.liferay.portal.security.sso.openid.connect.internal.service.filter.OpenIdConnectFilter.config`
* `com.liferay.portal.security.sso.openid.connect.internal.service.filter.OpenIdConnectSessionValidationFilter.config`

Im Anschluss muss das bundle `com.liferay.portal.security.sso.openid.connect.impl_3.0.4` einmal neu gestartet werden.

Anwendung
---------

Das Servicekonto ist ein OpenID Connect Provider. Für die Einrichtung muss daher 
ein neuer OpenID Connect Provider in Liferay konfiguriert werden. Die dazu notwendigen
Daten müssen vom jeweiligen Anbieter des Servicekontos bereitgestellt werden.

Neue OpenID Connect Provider werden unter Kontrollbereich > Konfiguration > Systemeinstellungen > Sicherheit > SSO hinterlegt. Generell wird OpenID Connect hier
unter dem Punkt *OpenID Connect* aktiviert. Unter *Provider OpenID Connect* kann ein neuer Eintrag für das Servicekonto hinterlegt werden.


Liferay-Versionen
-----------------

Dieses Plugin wurde erfolgreich in der folgenden Liferay-Version getestet:

* Liferay CE 7.1.3 GA4

Hinweise für Entwickler
-----------------------

Hintergrundinformationen zur Entwicklung können diesem Blog-Post entnommen werden: https://liferay.dev/blogs/-/blogs/integrating-german-servicekonto-with-liferay