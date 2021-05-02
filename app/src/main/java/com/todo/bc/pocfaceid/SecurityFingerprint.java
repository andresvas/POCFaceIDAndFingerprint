package com.todo.bc.pocfaceid;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.DialogInterface;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.view.View;
import android.widget.TableLayout;
import android.widget.Toast;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AlertDialog;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class SecurityFingerprint {

    private Context context;
    private boolean isActiveToast = false;
    private boolean isActiveAlert = false;

    public void setContext(Context context) {
        this.context = context;
    }

    public void setActiveToastAndActiveAlert(boolean activeToast, boolean activeAlert) {
        isActiveToast = activeToast;
        isActiveAlert = activeAlert;
    }

    private void showMessageAndLog(String message) {
        if (context != null && (isActiveToast || isActiveAlert)) {
            if (isActiveToast) {
                Toast.makeText(context, message, Toast.LENGTH_SHORT).show();
            }
            if (isActiveAlert) {
                createAndShowAlertMessage(message);
            }
        }
        String TAG_MESSAGE = "FINGER_T1";
        Log.d(TAG_MESSAGE, message);
    }

    private void createAndShowAlertMessage(String message) {
        AlertDialog alertDialog = new AlertDialog.Builder(context).create();
        alertDialog.setTitle("Fingerprint");
        alertDialog.setMessage(message);
        alertDialog.setButton(AlertDialog.BUTTON_NEUTRAL, "OK",
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                });
        alertDialog.show();
    }


    /**
     * this method retirn if android versions is sevne or higher
     *
     * @return version android
     */
    public Boolean isApiLevelSevenAndHigher() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.N;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public CredentialResponse isCredentialsValid(String key) {
        Cipher cipher = getCipher();
        SecretKey secretKey = getSecretKey(key);
        if (getSecretKey(key) == null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                generateSecretKey(new KeyGenParameterSpec.Builder(
                        key,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .setUserAuthenticationRequired(true)
                        // Invalidate the keys if the user has registered a new biometric
                        // credential, such as a new fingerprint. Can call this method only
                        // on Android 7.0 (API level 24) or higher. The variable
                        .setInvalidatedByBiometricEnrollment(true)
                        .build());
                //  Toast.makeText(this, "primera vez", Toast.LENGTH_SHORT).show();
                showMessageAndLog("first time, init key ");
            }
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            showMessageAndLog("Exitoso! En el registro de huellas no se ha agregado ninguno diferente a los previamente almacenados");
            return new  CredentialResponse(false,"credentials is valid, successful", 200);
        } catch (KeyPermanentlyInvalidatedException e) {
            showMessageAndLog("EL catalogo de huellas fue alterado, por favor realizar una autenticacion, para actualizar");
            return new CredentialResponse(false,"the fingerprint registration was altered",201 );
        } catch (InvalidKeyException e) {
            showMessageAndLog("El usuario aun no tiene una credencial nueva registrada, esto es debido a que posiblemente es su primera vez, se crea registro");
            e.printStackTrace();
            return new CredentialResponse(false,"do not have a registered credential, proceed to create for the next time",210 );

        }
    }

    public CredentialResponse updateCredential(String key) {
        try {
            showMessageAndLog("Se actualizo la crendicales de nuevo del usuario, debido a que se autentico satisfactoriamente");

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                generateSecretKey(new KeyGenParameterSpec.Builder(
                        key,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .setUserAuthenticationRequired(true)
                        // Invalidate the keys if the user has registered a new biometric
                        // credential, such as a new fingerprint. Can call this method only
                        // on Android 7.0 (API level 24) or higher. The variable
                        .setInvalidatedByBiometricEnrollment(true)
                        .build());
                return new  CredentialResponse(false,"update credentials, successful", 200);
            }

            return new CredentialResponse(true,"error version", 101);
        } catch (Exception e) {
            return new CredentialResponse(true,"error generic: "+ e.getMessage(),500 );
        }

    }

    public CredentialResponse disableValidateCredentials(String key) {
        showMessageAndLog("Se elimina la credencial que valida si agrego una huella nueva o no, con esto el boton de validar huella siempre lanzara exitoso");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            generateSecretKey(new KeyGenParameterSpec.Builder(
                    key,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(false)
                    // Invalidate the keys if the user has registered a new biometric
                    // credential, such as a new fingerprint. Can call this method only
                    // on Android 7.0 (API level 24) or higher. The variable
                    .setInvalidatedByBiometricEnrollment(false)
                    .build());
            return new  CredentialResponse(false,"disable credentials, successful", 200);
        }
        return new CredentialResponse(true,"error version", 101);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void generateSecretKey(KeyGenParameterSpec keyGenParameterSpec) {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(keyGenParameterSpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            showMessageAndLog("exception line 164: " + e.getMessage());
            e.printStackTrace();
        }

        keyGenerator.generateKey();
    }

    private SecretKey getSecretKey(String key) {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            showMessageAndLog("exception line 177: " + e.getMessage());
            e.printStackTrace();
        }
        // Before the keystore can be accessed, it must be loaded.
        try {
            return ((SecretKey) keyStore.getKey(key, null));
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            showMessageAndLog("exception line 184: " + e.getMessage());
            e.printStackTrace();
            return null;
        }


    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private Cipher getCipher() {
        try {
            return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }


    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public boolean isBiometryAvailable() {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (Exception e) {
            return false;
        }

        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        } catch (NoSuchAlgorithmException |
                NoSuchProviderException e) {
            return false;
        }

        if (keyGenerator == null || keyStore == null) {
            return false;
        }

        try {
            keyStore.load(null);
            keyGenerator.init(new
                    KeyGenParameterSpec.Builder("dummy_key",
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | CertificateException | IOException e) {
            return false;
        }
        return true;

    }


    @RequiresApi(api = Build.VERSION_CODES.M)
    private void getFingerprintInfo(Context context) {
        showMessageAndLog("method fingerprintInfo");
        try {
            FingerprintManager fingerprintManager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);
            @SuppressLint("DiscouragedPrivateApi") Method method = FingerprintManager.class.getDeclaredMethod("getEnrolledFingerprints");
            Object obj = method.invoke(fingerprintManager);

            if (obj != null) {
                Class<?> clazz = Class.forName("android.hardware.fingerprint.Fingerprint");
                Method getFingerId = clazz.getDeclaredMethod("getFingerId");

                for (int i = 0; i < ((List) obj).size(); i++) {
                    Object item = ((List) obj).get(i);
                    if (item != null) {
                        Log.d("TODO1", "fkie4. fingerId: " + getFingerId.invoke(item));
                    }
                }
            }
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

}
