package de.xdot.tlrz.openid.connect.internal;

import com.liferay.petra.string.StringBundler;
import com.liferay.petra.string.StringPool;
import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.exception.UserEmailAddressException;
import com.liferay.portal.kernel.model.Company;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.security.auth.PrincipalThreadLocal;
import com.liferay.portal.kernel.security.permission.PermissionChecker;
import com.liferay.portal.kernel.security.permission.PermissionCheckerFactoryUtil;
import com.liferay.portal.kernel.security.permission.PermissionThreadLocal;
import com.liferay.portal.kernel.service.CompanyLocalServiceUtil;
import com.liferay.portal.kernel.service.ServiceContext;
import com.liferay.portal.kernel.service.UserLocalServiceUtil;
import com.liferay.portal.kernel.util.PortalUtil;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.security.sso.openid.connect.OpenIdConnectServiceException;
import com.liferay.portal.security.sso.openid.connect.internal.OpenIdConnectUserInfoProcessor;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import de.xdot.tlrz.openid.connect.internal.exception.StrangersNotAllowedException;
import org.osgi.service.component.annotations.Component;

import java.text.ParseException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Locale;

@Component(
    immediate = true,
    service = OpenIdConnectUserInfoProcessor.class
)
public class OpenIdConnectUserInfoProcessorImpl implements OpenIdConnectUserInfoProcessor {

    public long processUserInfo(UserInfoSuccessResponse userInfoSuccessResponse, long companyId) throws PortalException {
        if (userInfoSuccessResponse.getUserInfo() != null) {
            return processUserInfo(userInfoSuccessResponse.getUserInfo(), companyId);
        } else {
            return processUserInfo(userInfoSuccessResponse.getUserInfoJWT(), companyId);
        }
    }

    private long processUserInfo(JWT userInfoJWT, long companyId) throws PortalException {
        try {
            JWTClaimsSet jwtClaimsSet = userInfoJWT.getJWTClaimsSet();

            String emailAddress = jwtClaimsSet.getStringClaim(UserInfo.EMAIL_CLAIM_NAME);

            User user = UserLocalServiceUtil.fetchUserByEmailAddress(
                companyId, emailAddress);

            if (user != null) {
                return user.getUserId();
            }

            checkAddUser(companyId, emailAddress);

            String firstName = jwtClaimsSet.getStringClaim(UserInfo.GIVEN_NAME_CLAIM_NAME);
            String lastName = jwtClaimsSet.getStringClaim(UserInfo.FAMILY_NAME_CLAIM_NAME);
            String middleName = jwtClaimsSet.getStringClaim(UserInfo.MIDDLE_NAME_CLAIM_NAME);

            int birthdayMonth = Calendar.JANUARY;
            int birthdayDay = 1;
            int birthdayYear = 1970;

            String birthdate = jwtClaimsSet.getStringClaim(UserInfo.BIRTHDATE_CLAIM_NAME);
            if (Validator.isNotNull(birthdate)) {
                LocalDate birthdateDate = LocalDate.parse(birthdate, DateTimeFormatter.ofPattern("yyyy-MM-dd"));

                birthdayYear = birthdateDate.getYear();
                birthdayMonth = birthdateDate.getMonthValue() - 1;
                birthdayDay = birthdateDate.getDayOfMonth();
            }

            return createUser(companyId, emailAddress, firstName, lastName, middleName, birthdayYear, birthdayMonth, birthdayDay);

        } catch (ParseException e) {
            throw new PortalException(e.getMessage(), e);
        }
    }

    @Override
    public long processUserInfo(UserInfo userInfo, long companyId)
            throws PortalException {

        String emailAddress = userInfo.getEmailAddress();

        User user = UserLocalServiceUtil.fetchUserByEmailAddress(
                companyId, emailAddress);

        if (user != null) {
            return user.getUserId();
        }

        checkAddUser(companyId, emailAddress);

        String firstName = userInfo.getGivenName();
        String lastName = userInfo.getFamilyName();

        if (Validator.isNull(firstName) || Validator.isNull(lastName) ||
                Validator.isNull(emailAddress)) {

            StringBundler sb = new StringBundler(9);

            sb.append("Unable to map OpenId Connect user to the portal, ");
            sb.append("missing or invalid profile information: ");
            sb.append("{emailAddresss=");
            sb.append(emailAddress);
            sb.append(", firstName=");
            sb.append(firstName);
            sb.append(", lastName=");
            sb.append(lastName);
            sb.append("}");

            throw new OpenIdConnectServiceException.UserMappingException(
                    sb.toString());
        }

        long creatorUserId = 0;
        boolean autoPassword = true;
        String password1 = null;
        String password2 = null;
        boolean autoScreenName = true;
        String screenName = StringPool.BLANK;
        long facebookId = 0;

        Company company = CompanyLocalServiceUtil.getCompany(companyId);

        Locale locale = company.getLocale();

        String middleName = userInfo.getMiddleName();
        long prefixId = 0;
        long suffixId = 0;
        boolean male = true;
        int birthdayMonth = Calendar.JANUARY;
        int birthdayDay = 1;
        int birthdayYear = 1970;
        String jobTitle = StringPool.BLANK;
        long[] groupIds = null;
        long[] organizationIds = null;
        long[] roleIds = null;
        long[] userGroupIds = null;
        boolean sendEmail = false;

        ServiceContext serviceContext = new ServiceContext();

        user = UserLocalServiceUtil.addUser(
                creatorUserId, companyId, autoPassword, password1, password2,
                autoScreenName, screenName, emailAddress, facebookId, null, locale,
                firstName, middleName, lastName, prefixId, suffixId, male,
                birthdayMonth, birthdayDay, birthdayYear, jobTitle, groupIds,
                organizationIds, roleIds, userGroupIds, sendEmail, serviceContext);

        user = UserLocalServiceUtil.updatePasswordReset(user.getUserId(), false);

        return user.getUserId();
    }

    private long createUser(long companyId, String emailAddress, String firstName, String lastName, String middleName, int birthdayYear, int birthdayMonth, int birthdayDay) throws PortalException {
        User user;
        if (Validator.isNull(firstName) || Validator.isNull(lastName) ||
            Validator.isNull(emailAddress)) {

            StringBundler sb = new StringBundler(9);

            sb.append("Unable to map OpenId Connect user to the portal, ");
            sb.append("missing or invalid profile information: ");
            sb.append("{emailAddresss=");
            sb.append(emailAddress);
            sb.append(", firstName=");
            sb.append(firstName);
            sb.append(", lastName=");
            sb.append(lastName);
            sb.append("}");

            throw new OpenIdConnectServiceException.UserMappingException(
                sb.toString());
        }

        long creatorUserId = 0;
        boolean autoPassword = true;
        String password1 = null;
        String password2 = null;
        boolean autoScreenName = true;
        String screenName = StringPool.BLANK;
        long facebookId = 0;

        Company company = CompanyLocalServiceUtil.getCompany(companyId);

        Locale locale = company.getLocale();

        long prefixId = 0;
        long suffixId = 0;
        boolean male = true;
        String jobTitle = StringPool.BLANK;
        long[] groupIds = null;
        long[] organizationIds = null;
        long[] roleIds = null;
        long[] userGroupIds = null;
        boolean sendEmail = false;

        ServiceContext serviceContext = new ServiceContext();

        String oldName = PrincipalThreadLocal.getName();
        PermissionChecker oldPermissionChecker = PermissionThreadLocal.getPermissionChecker();

        initializePermissionChecker();

        user = UserLocalServiceUtil.addUser(
            creatorUserId, companyId, autoPassword, password1, password2,
            autoScreenName, screenName, emailAddress, facebookId, null, locale,
            firstName, middleName, lastName, prefixId, suffixId, male,
            birthdayMonth, birthdayDay, birthdayYear, jobTitle, groupIds,
            organizationIds, roleIds, userGroupIds, sendEmail, serviceContext);

        user = UserLocalServiceUtil.updatePasswordReset(user.getUserId(), false);

        PrincipalThreadLocal.setName(oldName);
        PermissionThreadLocal.setPermissionChecker(oldPermissionChecker);

        return user.getUserId();
    }

    protected void checkAddUser(long companyId, String emailAddress)
		throws PortalException {

		Company company = CompanyLocalServiceUtil.getCompany(companyId);

		if (!company.isStrangers()) {
			throw new StrangersNotAllowedException(companyId);
		}

		if (!company.isStrangersWithMx() &&
			company.hasCompanyMx(emailAddress)) {

			throw new UserEmailAddressException.MustNotUseCompanyMx(
				emailAddress);
		}
	}

    public void initializePermissionChecker() throws PortalException {
        long companyId = PortalUtil.getDefaultCompanyId();

        User user = UserLocalServiceUtil.getDefaultUser(companyId);

        PermissionChecker checker;

        try {
            checker = PermissionCheckerFactoryUtil.create(user);
        } catch (Exception e) {
            throw new PortalException(e.getMessage(), e);
        }

        PermissionThreadLocal.setPermissionChecker(checker);

        PrincipalThreadLocal.setName(user.getUserId());
    }

}