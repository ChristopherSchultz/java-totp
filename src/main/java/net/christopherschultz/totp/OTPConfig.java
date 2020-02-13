package net.christopherschultz.totp;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Objects;

/**
 * Configuration for OTP (one-time password).
 *
 * Offers parsing of the Google-style OTP key URI format documented here:
 * https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 */
public class OTPConfig {
    // NOTE: DO NOT change these defaults; they are not preferences,
    // but spec-defined defaults.
    public static final String DEFAULT_OTP_HMAC_ALGORITHM = "SHA1";
    public static final int DEFAULT_OTP_DIGITS = 6;
    public static final int DEFAULT_OTP_PERIOD = 30;
    public static final int DEFAULT_OTP_COUNTER = 0;

    protected final String type;
    protected final String issuer;
    protected final String secret;
    protected final String algorithm;
    protected final int digits;
    protected final int period;
    protected final int counter;

    /**
     * Creates a new OTPConfig.
     *
     * @param type The type of OTP configuration e.g. <code>totp</code> or <code>hotp</code>.
     * @param issuer The issuer of the OTP configuration.
     * @param secret The secret/seed for the OTP algorithm, Base32-encoded without padding.
     * @param algorithm The algorithm to be used for OTP.
     * @param digits The number of output digits to be used.
     * @param period The time interval between token changes (TOTP only).
     * @param counter The initial counter value (HOTP only).
     */
    public OTPConfig(String type, String issuer, String secret, String algorithm, int digits, int period, int counter) {
        this.type = type;
        this.issuer = issuer;
        this.secret = secret;
        this.algorithm = algorithm;
        this.digits = digits;
        this.period = period;
        this.counter = counter;
    }

    /**
     * Gets the type of OTP configuration.
     *
     * @return The type of OTP configuration e.g. <code>totp</code> or <code>hotp</code>.
     */
    public String getType() {
        return type;
    }

    /**
     * Gets the issuer of the OTP configuration.
     *
     * @return The issuer of the OTP configuration.
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Gets the secret or seed of the OTP configuration.
     *
     * @return The secret/seed of the OTP configuration, Base32-encoded without padding.
     */
    public String getSecret() {
        return secret;
    }

    /**
     * Gets the OTP algorithm to use.
     *
     * @return The OTP algorithm to use e.g. SHA1, SHA256.
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Gets the number of token digits to use.
     *
     * @return The number of token digits to use (usually 6 or 8).
     */
    public int getDigits() {
        return digits;
    }

    /**
     * Gets the period, in seconds, of the TOTP time intervals.
     * This is only valid if the type is TOTP.
     *
     * @return The period, in seconds, of the TOTP time intervals.
     */
    public int getPeriod() {
        return period;
    }

    /**
     * Gets the initial value of the HOTP counter.
     * This is only valid if the type is HOTP.
     *
     * @return The initial value for the HOTP counter.
     */
    public int getCounter() {
        return counter;
    }

    /**
     * Returns a string representation of this OTPConfig in the
     * format described here:
     * https://github.com/google/google-authenticator/wiki/Key-Uri-Format
     *
     * Any default values will be omitted.
     *
     * @return A String representation of this OTPConfig.
     */
    @Override
    public String toString() {
        try {
            StringBuilder sb = new StringBuilder("otpauth://").append(URLEncoder.encode(type, "UTF-8")).append('/');
            if(null != issuer)
                sb.append(issuer);

            sb.append("?secret=").append(URLEncoder.encode(secret, "UTF-8"));

            if(!Objects.equals(DEFAULT_OTP_HMAC_ALGORITHM, algorithm))
                sb.append("&algorithm=").append(URLEncoder.encode(algorithm, "UTF-8"));

            if(DEFAULT_OTP_DIGITS != digits)
                sb.append("&digits=").append(digits);
            if(DEFAULT_OTP_COUNTER != counter)
                sb.append("&counter=").append(counter);
            if(DEFAULT_OTP_PERIOD != period)
                sb.append("&period=").append(period);

            return sb.toString();
        } catch (UnsupportedEncodingException uee) {
            throw new InternalError("UTF-8 is not supported");
        }
    }

    /**
     * Parses an OTP configuration string of the form described by
     * https://github.com/google/google-authenticator/wiki/Key-Uri-Format
     *
     * Briefly:
     * <code>otpauth://TYPE/LABEL?PARAMETERS</code>
     * TYPE is: hotp, totp -- but any type value is supported, as long as it does not contain a '/' character.
     *
     * label is what should be shown in an authenticator as an auth label
     *
     * Recognized parameters are: secret, issuer, algorithm, digits, counter, period
     *
     * @param config The configuration string.
     *
     * @return An OTPConfig with all the fields set properly.
     */
    public static OTPConfig parseOTPConfig(String config) {
        // This URI format is fully-documented here:
        //
        // https://github.com/google/google-authenticator/wiki/Key-Uri-Format
        //
        // Briefly:
        // otpauth://TYPE/LABEL?PARAMETERS
        //
        // type is: hotp, totp
        // label is what should be shown in an authenticator as an auth label
        // recognized parameters are: secret, issuer, algorithm, digits, counter, period
        //
        if(!config.startsWith("otpauth://"))
            throw new IllegalArgumentException("Configuration does not appear to be for OTP-based authentication");

        int pos = config.indexOf('/', 10);
        if(pos < 0)
            throw new IllegalArgumentException("Unrecognized otp config format");

        String type = config.substring(10, pos);

        pos = config.indexOf('?', pos + 1);
        if(0 > pos)
            throw new IllegalArgumentException("Unrecognized otp config format");

        String issuer = config.substring(15, pos);
        if(0 == issuer.length())
            issuer = null;

        String parameterPart = config.substring(pos + 1);

        String[] parameters = parameterPart.split("&");

        HashMap<String,String> params = new HashMap<String,String>(parameters.length);

        for(String param : parameters) {
            String[] s = param.split("=");

            if(null == s || 0 == s.length) {
                // Ignore this "parameter"
            } else if(s.length == 1) {
                params.put(s[0], "");
            } else {
                params.put(s[0], s[1]);
            }
        }
        String secret = params.get("secret");

        if(null == secret)
            throw new IllegalArgumentException("OTP config contains no secret");

        String algorithm = params.get("algorithm");
        if(null == algorithm)
            algorithm = DEFAULT_OTP_HMAC_ALGORITHM;

        int digits = DEFAULT_OTP_DIGITS;
        int period = DEFAULT_OTP_PERIOD;
        int counter = DEFAULT_OTP_COUNTER;

        if(null != params.get("digits"))
            digits = Integer.parseInt(params.get("digits"));
        if(null != params.get("period"))
            period = Integer.parseInt(params.get("period"));
        if(null != params.get("counter"))
            counter = Integer.parseInt(params.get("counter"));

        if(period < 10)
            period = 10;
        if(period > 120)
            period = 120;

        if(digits < 6)
            digits = 6;
        if(digits > 20)
            digits = 20;

        return new OTPConfig(type, issuer, secret, algorithm, digits, period, counter);
    }
}
