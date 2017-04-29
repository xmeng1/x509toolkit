package io.github.xmeng1;

/**
 * User:    Xin Meng
 * Date:    29/04/17
 * Project: x509toolkit
 */
public class X509ToolKitException extends Exception {

    /**
     * Constructs a X509ToolKitException with no detail message.
     */
    public X509ToolKitException() {
        super();
    }

    /**
     * Constructs a X509ToolKitException with the specified detail
     * message.
     * A detail message is a String that describes this particular
     * exception.
     *
     * @param message the detail message.
     */
    X509ToolKitException(String message) {
        super(message);
    }

    /**
     * Creates a {@code X509ToolKitException} with the specified
     * detail message and cause.
     *
     * @param message the detail message (which is saved for later retrieval
     *        by the {@link #getMessage()} method).
     * @param cause the cause (which is saved for later retrieval by the
     *        {@link #getCause()} method).  (A {@code null} value is permitted,
     *        and indicates that the cause is nonexistent or unknown.)
     * @since 1.5
     */
    public X509ToolKitException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Creates a {@code X509ToolKitException} with the specified cause
     * and a detail message of {@code (cause==null ? null : cause.toString())}
     * (which typically contains the class and detail message of
     * {@code cause}).
     *
     * @param cause the cause (which is saved for later retrieval by the
     *        {@link #getCause()} method).  (A {@code null} value is permitted,
     *        and indicates that the cause is nonexistent or unknown.)
     * @since 1.5
     */
    public X509ToolKitException(Throwable cause) {
        super(cause);
    }
}
