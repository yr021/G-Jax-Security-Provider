
package com.rac021.jax.security.provider.configuration ;

import java.io.File ;
import java.util.Map ;
import java.util.List ;
import javax.ejb.Startup ;
import java.util.HashMap ;
import java.io.FileReader ;
import javax.inject.Singleton ;
import com.esotericsoftware.yamlbeans.YamlReader ;
import com.rac021.jax.api.qualifiers.security.Policy ;
import com.rac021.jax.api.configuration.IConfigurator ;

/**
 *
 * @author ryahiaoui
 */

@Singleton
@Startup
public class Configurator implements IConfigurator {

    private String pathConfig          = "serviceConf.yaml" ;
    private Map    configuration       = new HashMap()      ;
    private String authenticationType  = null               ;
    
    private String tableName           = "users"    ;
    private String loginColumnName     = "login"    ;
    private String passwordColumnName  = "password" ;
    private String passwordStorage     = "MD5"      ;
    private String algoSign            = "SHA1"     ;
    
    private String loginSignature      = "PLAIN"    ;
    private String passwordSignature   = "MD5"      ;
    private String timeStampSignature  = "PLAIN"    ;
    private Long   validRequestTimeout = 30l        ;
    
    private String keycloakFile        = null       ;
    
    Map<String ,String >  security                  ;
    
    public Configurator() {

        security = new HashMap<>() ;
        
        try {
             if(System.getProperty("serviceConf") != null) {
                 pathConfig = System.getProperty("serviceConf") ;
             }
             
             if( pathConfig != null && new File(pathConfig).exists() ) {
                 YamlReader reader = new YamlReader(new FileReader(pathConfig)) ;
                 Object     object = reader.read() ;
                 Map        map    = (Map)object   ;            
                 configuration     = map           ;

                 setAuthenticationType() ;
                 setCredentials()        ;
                 setAlgoSign()           ;
                 setParams()             ;
                 setSecurity()           ;
             }
            
           } catch( Exception ex ) {
               ex.printStackTrace() ;       
           }
    }

    public  Map getConfiguration() {
        return configuration;
    }
    
   private void setAuthenticationType() {
       
      if( ((Map)this.configuration.get("authentication")) == null )  {
          authenticationType = Policy.Public.name().toLowerCase() ;
      }
      else {
          
         authenticationType = (String) ((Map)this.configuration.get("authentication")).get( "type" )
                                                 .toString().replaceAll(" +", " ").trim()          ; 
         
         if( authenticationType.equalsIgnoreCase(Policy.SSO.name()))
             keycloakFile  =  (String) ((Map)this.configuration
                                                 .get("authentication")).get( "keycloakFile" )
                                                 .toString().replaceAll(" +", " ").trim()    ; 
      }
   }
   
   public String getAuthenticationType() {      
       return authenticationType ;
   }
   
   public Map getAuthenticationInfos() {
       return (Map)((Map) this.configuration.get("authentication")) ;
   }

    public String getAuthenticationType(String serviceCode) {
      return security.getOrDefault(serviceCode, Policy.Public.name().toLowerCase() ) ;
    }

    public String getPathConfig() {
        return pathConfig ;
    }

    public String getTableName() {
        return tableName ;
    }

    public String getLoginColumnName() {
        return loginColumnName ;
    }

    public String getPasswordColumnName() {
        return passwordColumnName ;
    }

    public String getLoginSignature() {
        return loginSignature ;
    }

    public String getPasswordSignature() {
        return passwordSignature;
    }

    public String getTimeStampSignature() {
        return timeStampSignature ;
    }

    public Map<String, String> getSecurity() {
        return security ;
    }

    public String getKeycloakFile() {
        return keycloakFile ;
    }

    public void setKeycloakFile(String keycloakFile) {
        this.keycloakFile = keycloakFile ;
    }

    @Override
    public Long getValidRequestTimeout() {
        return validRequestTimeout;
    }

    
    public String getPasswordStorage() {
        return passwordStorage ;
    }
   
    private void setAlgoSign() {
        
         if( this.configuration.get("authentication") != null ) {
             
            if( ( ( (String) ((Map)this.configuration.get("authentication")).get("type"))
                                                     .equalsIgnoreCase(Policy.CustomSignOn.name()))) {
               this.algoSign = (String) ((Map)this.configuration.get("authentication"))
                                                  .get("algoSign")
                                                  .toString().replaceAll(" +", " ").trim() ;         
            }
         }
    }

    public String getAlgoSign() {
        return algoSign ;
    }
    
    private void setParams() {
        
        if( this.configuration.get("authentication") != null ) {
            if( ( ( (String) ((Map)this.configuration.get("authentication")).get("type")).equalsIgnoreCase(Policy.CustomSignOn.name())) ) {
               this.loginSignature      = (String) ( (Map) ((Map)this.configuration.get("authentication")).get("paramToSign")).get("login").toString().replaceAll(" +", " ").trim()     ;
               this.passwordSignature   = (String) ( (Map) ((Map)this.configuration.get("authentication")).get("paramToSign")).get("password").toString().replaceAll(" +", " ").trim()  ;
               this.timeStampSignature  = (String) ( (Map) ((Map)this.configuration.get("authentication")).get("paramToSign")).get("timeStamp").toString().replaceAll(" +", " ").trim() ;
               this.validRequestTimeout = Long.parseLong( ( (String) ((Map)this.configuration.get("authentication")).get("validRequestTimeout")) ) ;
            }
        }
    }

    private void setSecurity() {
        
        if( getAuthenticationType() == null ) {
            authenticationType = Policy.Public.name().toLowerCase() ;
            return ;
        }
        
        if( getAuthenticationType().equalsIgnoreCase(Policy.SSO.name())) {
           if( getAuthenticationInfos() != null ) {
              ((Map)getAuthenticationInfos().get("secured")).keySet().forEach( _sName -> {
                   security.put((String) _sName, Policy.SSO.name() ) ;
              }) ;
           }
        }
        else if( getAuthenticationType().equalsIgnoreCase(Policy.CustomSignOn.name())) {
           if( getAuthenticationInfos() != null ) {
             ((List<String>)getAuthenticationInfos().get("secured")).forEach( _sName -> {
                security.put(_sName, Policy.CustomSignOn.name() ) ;
             }) ; 
           }
        }
    }
     
    private void setCredentials() {
        
        if( this.configuration.get("authentication") != null ) {
            if( ( ( (String) ((Map) this.configuration.get("authentication")).get("type")).equalsIgnoreCase(Policy.CustomSignOn.name())) ) {
                this.tableName          = ( String) ( (Map) ((Map)this.configuration.get("authentication")).get("credentials")).get("tableName").toString().replaceAll(" +", " ").trim()                 ;
                this.loginColumnName    = ( String) ( (Map) ((Map)this.configuration.get("authentication")).get("credentials")).get("loginColumnName").toString().replaceAll(" +", " ").trim()           ;
                this.passwordColumnName = ((String) ( (Map) ((Map)this.configuration.get("authentication")).get("credentials")).get("passwordColumnName")).replaceAll(" +", " ").split(" -> ")[0].trim() ; 

                this.passwordStorage = ((String) ( (Map) ((Map)this.configuration.get("authentication")).get("credentials")).get("passwordColumnName")).contains(" -> ") ?
                                       ((String) ( (Map) ((Map)this.configuration.get("authentication")).get("credentials")).get("passwordColumnName")).replaceAll(" +", " ").trim().split(" -> ")[1]    :
                                       "plain" ;
            }
        }
    }
}
