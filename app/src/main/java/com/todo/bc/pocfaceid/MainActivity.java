package com.todo.bc.pocfaceid;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.annotation.SuppressLint;
import android.content.Context;
import android.hardware.biometrics.BiometricManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

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

public class MainActivity extends AppCompatActivity {
   // private final String key = "RETRIEVE";

    private TextView textViewValue;
    private  SecurityFingerprint securityFingerprint;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        securityFingerprint = new SecurityFingerprint();
        securityFingerprint.setContext(this);
        securityFingerprint.setActiveToastAndActiveAlert(false,true);

        textViewValue = findViewById(R.id.textViewValue);

        textViewValue.setText("");


    }

    public void isHasFinger() {
        // BiometricManager.from(this).canAuthenticate();
    }

    public void pressButton(View view) {
        // Toast.makeText(this, "test", Toast.LENGTH_SHORT).show();

        if (securityFingerprint.isApiLevelSevenAndHigher()) {
            if (securityFingerprint.isBiometryAvailable()) {
                //validateFinger();
                 final String key = "TODO1";
                securityFingerprint.isCredentialsValid(key);
            } else {
                textViewValue.setText("Este dispositvio no tiene la capacidad para el uso registro y autenticación por huella O no tienes huellas registradas actualmente en el dispositivo");
            }

        } else {
            textViewValue.setText("Esta version de android no tiene la Api soportada para huella");
        }

    }


    @RequiresApi(api = Build.VERSION_CODES.M)
    private void validateFinger() {
        Cipher cipher = getCipher();
         final String key = "RETRIEVE";
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
            }
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            System.out.print("La clave no cambio");
            Toast.makeText(this, "NO change password", Toast.LENGTH_LONG).show();
        } catch (KeyPermanentlyInvalidatedException e) {
            System.out.print("cambio la clave");
            Toast.makeText(this, "SI change password", Toast.LENGTH_SHORT).show();


            //Toast.makeText(MainActivity.this, "changed", Toast.LENGTH_LONG).show();

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
            }
        } catch (InvalidKeyException e) {
            Toast.makeText(this, "NO  credentials yet or it had error", Toast.LENGTH_SHORT).show();
            e.printStackTrace();

        }
    }


    public Boolean isApiLevelSevenAndHigher() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.N;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void isCredentialsValid(String key) {
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
                Toast.makeText(this, "primera vez", Toast.LENGTH_SHORT).show();
            }
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            textViewValue.setText("Exitoso! En el registro de huellas no se ha agregado ninguno diferente a los previamente almacenados");
        } catch (KeyPermanentlyInvalidatedException e) {
            textViewValue.setText("EL catalogo de huellas fue alterado, por favor realizar una autenticacion, para actualizar");
        } catch (InvalidKeyException e) {
            textViewValue.setText("El usuario aun no tiene una credencial nueva registrada, esto es debido a que posiblemente es su primera vez, se crea registro");
            e.printStackTrace();
        }
    }

    public boolean updateCredential(String key) {
        try {
            textViewValue.setText("Se actualizo la crendicales de nuevo del usuario, debido a que se autentico satisfactoriamente");
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
                return true;
            }
            return false;
        } catch (Exception e) {
            return false;
        }

    }

    public void disableValidateCredentials(String key) {
        textViewValue.setText("Se elimina la credencial que valida si agrego una huella nueva o no, con esto el boton de validar huella siempre lanzara exitoso");
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
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void generateSecretKey(KeyGenParameterSpec keyGenParameterSpec) {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(keyGenParameterSpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            textViewValue.setText("exception line 187: " + e.getMessage());

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
            textViewValue.setText("exception line 199: " + e.getMessage());
            e.printStackTrace();
        }
        // Before the keystore can be accessed, it must be loaded.
        try {
            return ((SecretKey) keyStore.getKey(key, null));
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            textViewValue.setText("exception line 206: " + e.getMessage());
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
    public void otherButton(View view) {
         final String key = "TODO1";
        securityFingerprint.updateCredential(key);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void getFingerprintInfo(Context context) {
        Toast.makeText(context, "FINGERID", Toast.LENGTH_SHORT).show();
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

    public void disableFinger(View view) {
         final String key = "TODO1";
        securityFingerprint.disableValidateCredentials(key);
    }
}