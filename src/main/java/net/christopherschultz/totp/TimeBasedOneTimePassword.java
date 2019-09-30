package net.christopherschultz.totp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

/**
 * Implementation of a time-based one-time password compliant with
 * <a href="https://tools.ietf.org/html/rfc6238">RFC 6238</a>.
 *
 * This class is thread-safe after initialization as long as none
 * of the algorithm parameters are changed after initialization.
 *
 * @author Christopher Schultz
 */
public class TimeBasedOneTimePassword {
    // All defaults are specified by RFC 6238
    private String hmacAlgorithm = "HmacSHA1";
    private long interval = 30000l; // Default = 30s
    private long epoch = 0;         // Default = Unix epoch
    private int tokenLength = 6;    // Default 6 characters
    private int validIntervals = 2; // The number of intervals for which a token will be valid

    /**
     * Sets the HMAC algorithm to be used.
     *
     * @param hmacAlgorithm The algorithm to use, e.g. HmacSHA1,
     *                      HmacSHA256, etc. The default is
     *                      <code>HmacSHA1</code>.
     */
    public void setHmacAlgorithm(String hmacAlgorithm) {
        this.hmacAlgorithm = hmacAlgorithm;
    }

    /**
     * Sets the epoch (T0 value) for time intervals.
     *
     * @param epoch Time in milliseconds for the beginning of the epoch.
     *              The default is 0 (UNIX epoch).
     */
    public void setEpoch(long epoch) {
        this.epoch = epoch;
    }

    /**
     * Sets the time-interval or time-step value.
     *
     * @param interval The number of milliseconds in a time-interval/time-step.
     *                 The default is 30000 (30sec).
     */
    public void setInterval(long interval) {
        this.interval = interval;
    }

    /**
     * Sets the generated token length.
     *
     * @param tokenLength The token length in characters. The default is 6.
     */
    public void setTokenLength(int tokenLength) {
        this.tokenLength = tokenLength;
    }

    /**
     * Sets the number of intervals for which a token will be valid.
     * This allows for a bit of clock skew between the prover
     * and the verifier and also for a bit of transmission lag between
     * the two parties.
     *
     * @param intervals The number of intervals to allow to be valid.
     */
    public void setValidIntervals(int intervals) {
        this.validIntervals = intervals;
    }

    /**
     * Returns long value as a byte array in network byte order.
     *
     * @param l
     *
     * @return An array of 8 bytes containing the raw bytes of the long l.
     */
    private static final byte[] toBytes(long l) {
        return new byte[] {
                (byte)((l >> 56) & 0xff),
                (byte)((l >> 48) & 0xff),
                (byte)((l >> 40) & 0xff),
                (byte)((l >> 32) & 0xff),
                (byte)((l >> 24) & 0xff),
                (byte)((l >> 16) & 0xff),
                (byte)((l >>  8) & 0xff),
                (byte)((l >>  0) & 0xff)
        };
    }

    /**
     * Gets the token for the specified time-interval count.
     *
     * @param mac The initialized HMAC object.
     * @param C The interval count to use.
     *
     * @return The token for the specified interval count.
     */
    protected String getToken(Mac mac, long C)
    {
        mac.reset();
        byte[] H = mac.doFinal(toBytes(C));
        int O = H[H.length - 1] & 0x0f;

        int I = ((H[O] & 0xff)     << 24
                | (H[O + 1] & 0xff) << 16
                | (H[O + 2] & 0xff) <<  8
                | (H[O + 3] & 0xff))
                ;

        I = I & 0x7fffffff;

        String token = Integer.toString(I, 10);
        if(token.length() < tokenLength) {
            do
                token = "0" + token;
            while(token.length() < tokenLength);
        } else
            token = token.substring(token.length() - tokenLength);

        return token;
    }

    /**
     * Gets the TOTP token valid for the specified interval count.
     *
     * @param seed The TOTP seed (secret).
     * @param count The interval count from the epoch.
     *
     * @return The TOTP token valid for the specified interval count.
     *
     * @throws InvalidKeyException If there is a problem with the TOTP seed.
     * @throws NoSuchAlgorithmException If the HMAC algorithm is unsupported.
     */
    public String getToken(byte[] seed, long count)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        Mac mac = Mac.getInstance(hmacAlgorithm);
        mac.init(new SecretKeySpec(seed, hmacAlgorithm));

        return getToken(mac, count);
    }

    /**
     * Gets the currently-valid TOTP token given the current time.
     *
     * @param seed The TOTP seed (secret).
     *
     * @return The currently-valid TOTP token.
     *
     * @throws InvalidKeyException If there is a problem with the TOTP seed.
     * @throws NoSuchAlgorithmException If the HMAC algorithm is unsupported.
     */
    public String getToken(String seed) throws InvalidKeyException, NoSuchAlgorithmException
    {
        byte[] seedBytes = new Base32().decode(seed);

        long count = (System.currentTimeMillis() - this.epoch) / this.interval;

        return getToken(seedBytes, count);
    }

    /**
     * Gets a list of tokens valid for <code>intervals</code> around the
     * current time-interval (based upon the current time). The oldest
     * valid token is found at the zeroth position in the return array,
     * and the newest valid token is found at the last position.
     * The currently-valid token is roughly centered in the array.
     *
     * This method allows a certain amount of clock-skew between client
     * and server for the convenience of users, so that the TOTP token
     * they obtain from their token-generating device does not expire
     * during the time it takes to transcribe it into a login form.
     *
     * @param seed The TOTP seed (secret).
     * @param intervals The number of intervals to return, maximum of 5.
     *
     * @return An array of <code>intervals</code> tokens which are valid
     *         either currently or just before or after the currently-valid
     *         token.
     *
     * @throws InvalidKeyException If there is a problem with the TOTP seed.
     * @throws NoSuchAlgorithmException If the HMAC algorithm is unsupported.
     */
    public String[] getTokens(String seed, int intervals) throws InvalidKeyException, NoSuchAlgorithmException
    {
        byte[] seedBytes = new Base32().decode(seed);

        return getTokens(seedBytes, intervals);
    }

    /**
     * Gets a list of tokens valid for <code>intervals</code> around the
     * current time-interval (based upon the current time). The oldest
     * valid token is found at the zeroth position in the return array,
     * and the newest valid token is found at the last position.
     * The currently-valid token is roughly centered in the array.
     *
     * This method allows a certain amount of clock-skew between client
     * and server for the convenience of users, so that the TOTP token
     * they obtain from their token-generating device does not expire
     * during the time it takes to transcribe it into a login form.
     *
     * @param seed The TOTP seed (secret).
     * @param intervals The number of intervals to return, maximum of 5.
     *
     * @return An array of <code>intervals</code> tokens which are valid
     *         either currently or just before or after the currently-valid
     *         token.
     *
     * @throws InvalidKeyException If there is a problem with the TOTP seed.
     * @throws NoSuchAlgorithmException If the HMAC algorithm is unsupported.
     */
    public String[] getTokens(byte[] seed, int intervals)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        if(intervals > 5)
            throw new IllegalArgumentException("Too many intervals");

        String[] tokens = new String[intervals];

        Mac mac = Mac.getInstance(hmacAlgorithm);
        mac.init(new SecretKeySpec(seed, hmacAlgorithm));

        long count = (System.currentTimeMillis() - this.epoch) / this.interval;
        count -= intervals / 2; // Back-up 1/2 of the intervals

        for(int i=0; i<intervals; ++i)
            tokens[i] = getToken(mac, count++);

        return tokens;
    }

    /**
     * Checks to see if the specified token is currently valid.
     *
     * This method checks to see if the specified token is valid
     * either during the current interval or some number of intervals
     * "around" the current interval, as specified by calling
     * {@link #setValidIntervals}.
     *
     * @param seed The TOTP seed (secret).
     * @param token The token to verify.
     *
     * @return <code>true</code> if the token is currently valid,
     *         <code>false</code> otherwise.
     *
     * @throws InvalidKeyException If there is a problem with the TOTP seed.
     * @throws NoSuchAlgorithmException If the HMAC algorithm is unsupported.
     */
    public boolean isTokenValid(String seed, String token)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        for(String validToken : getTokens(seed, this.validIntervals))
            if(validToken.equals(token))
                return true;

        return false;
    }

    /**
     * Checks to see if the specified token is currently valid.
     *
     * This method checks to see if the specified token is valid
     * either during the current interval or some number of intervals
     * "around" the current interval, as specified by calling
     * {@link #setValidIntervals}.
     *
     * @param seed The TOTP seed (secret).
     * @param token The token to verify.
     *
     * @return <code>true</code> if the token is currently valid,
     *         <code>false</code> otherwise.
     *
     * @throws InvalidKeyException If there is a problem with the TOTP seed.
     * @throws NoSuchAlgorithmException If the HMAC algorithm is unsupported.
     */
    public boolean isTokenValid(byte[] seed, String token)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        for(String validToken : getTokens(seed, this.validIntervals))
            if(validToken.equals(token))
                return true;

        return false;
    }

    public static void main(String[] args) throws Exception {
        if(args.length < 1) {
            System.out.println("Usage: " + TimeBasedOneTimePassword.class.getName() + " <TOTP key>");
            System.out.println("The TOTP key should be a Base32-encoded TOTP seed value.");
            System.out.println();
            System.out.println("This program will output the previous, current, and next-valid TOTP tokens for the given seed.");
        } else {
            TimeBasedOneTimePassword totp = new TimeBasedOneTimePassword();
            System.out.println(java.util.Arrays.asList(totp.getTokens(args[0], 3)));
        }
    }
}
