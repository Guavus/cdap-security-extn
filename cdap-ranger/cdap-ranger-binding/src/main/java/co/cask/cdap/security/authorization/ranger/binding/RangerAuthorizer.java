/*
 * Copyright © 2017 Cask Data, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */
package co.cask.cdap.security.authorization.ranger.binding;

import co.cask.cdap.proto.element.EntityType;
import co.cask.cdap.proto.id.ApplicationId;
import co.cask.cdap.proto.id.ArtifactId;
import co.cask.cdap.proto.id.DatasetId;
import co.cask.cdap.proto.id.DatasetModuleId;
import co.cask.cdap.proto.id.DatasetTypeId;
import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.id.InstanceId;
import co.cask.cdap.proto.id.KerberosPrincipalId;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.proto.id.ProgramId;
import co.cask.cdap.proto.id.SecureKeyId;
import co.cask.cdap.proto.id.StreamId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Authorizable;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.proto.security.Privilege;
import co.cask.cdap.proto.security.Role;
import co.cask.cdap.proto.security.Principal.PrincipalType;
import co.cask.cdap.security.spi.authorization.AbstractAuthorizer;
import co.cask.cdap.security.spi.authorization.AuthorizationContext;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import com.google.common.base.Preconditions;
import java.net.InetAddress;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;
import javax.security.auth.Subject;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.policyengine.RangerAccessRequest.ResourceMatchingScope;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RangerAuthorizer extends AbstractAuthorizer {
   private static final Logger LOG = LoggerFactory.getLogger(RangerAuthorizer.class);
   private static volatile RangerBasePlugin rangerPlugin = null;
   private AuthorizationContext context;
   private String instanceName;

   public synchronized void initialize(AuthorizationContext context) throws Exception {
      this.context = context;
      Properties properties = context.getExtensionProperties();
      this.instanceName = properties.containsKey("instance.name") ? properties.getProperty("instance.name") : "cdap";
      if (rangerPlugin == null) {
         UserGroupInformation ugi = UserGroupInformation.getLoginUser();
         Preconditions.checkNotNull(ugi, "Kerberos login information is not available. UserGroupInformation is null");
         MiscUtil.setUGILoginUser(ugi, (Subject)null);
         LOG.debug("Initializing Ranger CDAP Plugin with UGI {}", ugi);
         rangerPlugin = new RangerBasePlugin("cdap", "cdap");
      }

      rangerPlugin.init();
      RangerDefaultAuditHandler auditHandler = new RangerDefaultAuditHandler();
      rangerPlugin.setResultProcessor(auditHandler);
   }

   public void enforce(EntityId entity, Principal principal, Action action) throws Exception {
      if (!this.enforce(entity, principal, ResourceMatchingScope.SELF, this.toRangerAccessType(action))) {
         throw new UnauthorizedException(principal, action, entity);
      }
   }

   public void enforce(EntityId entityId, Principal principal, Set<Action> set) throws Exception {
      LOG.debug("Enforce called on entity {}, principal {}, actions {}", new Object[]{entityId, principal, set});
      Iterator var4 = set.iterator();

      while(var4.hasNext()) {
         Action action = (Action)var4.next();
         this.enforce(entityId, principal, action);
      }

   }

   public Set<? extends EntityId> isVisible(Set<? extends EntityId> entityIds, Principal principal) throws Exception {
      Set<EntityId> visibleEntities = new HashSet(entityIds.size());
      Iterator var4 = entityIds.iterator();

      while(var4.hasNext()) {
         EntityId entityId = (EntityId)var4.next();
         if (this.enforce(entityId, principal, ResourceMatchingScope.SELF_OR_DESCENDANTS, "_any")) {
            visibleEntities.add(entityId);
         }
      }

      return visibleEntities;
   }

   public void grant(Authorizable authorizable, Principal principal, Set<Action> set) throws Exception {
      throw new UnsupportedOperationException("Please use Ranger Admin UI to grant privileges.");
   }

   public void revoke(Authorizable authorizable, Principal principal, Set<Action> set) throws Exception {
      throw new UnsupportedOperationException("Please use Ranger Admin UI to revoke privileges.");
   }

   public void revoke(Authorizable authorizable) throws Exception {
      throw new UnsupportedOperationException("Please use Ranger Admin UI to revoke privileges.");
   }

   public void createRole(Role role) throws Exception {
      throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");
   }

   public void dropRole(Role role) throws Exception {
      throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");
   }

   public void addRoleToPrincipal(Role role, Principal principal) throws Exception {
      throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");
   }

   public void removeRoleFromPrincipal(Role role, Principal principal) throws Exception {
      throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");
   }

   public Set<Role> listRoles(Principal principal) throws Exception {
      throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");
   }

   public Set<Role> listAllRoles() throws Exception {
      throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");
   }

   public Set<Privilege> listPrivileges(Principal principal) throws Exception {
      throw new UnsupportedOperationException("Please use Ranger Admin UI to list privileges.");
   }

   private boolean enforce(EntityId entity, Principal principal, ResourceMatchingScope resourceMatchingScope, String accessType) throws Exception {
      LOG.debug("Enforce called on entity {}, principal {}, action {} and match scope {}", new Object[]{entity, principal, accessType, resourceMatchingScope});
      if (rangerPlugin == null) {
         throw new RuntimeException("CDAP Ranger Authorizer is not initialized.");
      } else if (principal.getType() != PrincipalType.USER) {
         throw new IllegalArgumentException(String.format("The principal type for current enforcement request is '%s'. Authorization enforcement is only supported for '%s'.", principal.getType(), PrincipalType.USER));
      } else {
         String requestingUser = principal.getName();
         String ip = InetAddress.getLocalHost().getHostName();
         Set<String> userGroups = MiscUtil.getGroupsForRequestUser(requestingUser);
         LOG.debug("Requesting user {}, ip {}, requesting user groups {}", new Object[]{requestingUser, ip, userGroups});
         Date eventTime = new Date();
         RangerAccessRequestImpl rangerRequest = new RangerAccessRequestImpl();
         rangerRequest.setUser(requestingUser);
         rangerRequest.setUserGroups(userGroups);
         rangerRequest.setClientIPAddress(ip);
         rangerRequest.setAccessTime(eventTime);
         rangerRequest.setResourceMatchingScope(resourceMatchingScope);
         RangerAccessResourceImpl rangerResource = new RangerAccessResourceImpl();
         rangerRequest.setResource(rangerResource);
         rangerRequest.setAccessType(accessType);
         this.setAccessResource(entity, rangerResource);
         boolean isAuthorized = false;

         try {
            RangerAccessResult result = rangerPlugin.isAccessAllowed(rangerRequest);
            if (result == null) {
               LOG.warn("Unauthorized: Ranger Plugin returned null for this authorization enforcement.");
               isAuthorized = false;
            } else {
               isAuthorized = result.getIsAllowed();
            }
         } catch (Throwable var16) {
            LOG.warn("Error while calling isAccessAllowed(). request {}", rangerRequest, var16);
            throw var16;
         } finally {
            LOG.trace("Ranger Request {}, authorization {}.", rangerRequest, isAuthorized ? "successful" : "failed");
         }

         return isAuthorized;
      }
   }

   private String toRangerAccessType(Action action) {
      return action.toString().toLowerCase();
   }

   private void setAccessResource(EntityId entityId, RangerAccessResourceImpl rangerAccessResource) {
      EntityType entityType = entityId.getEntityType();
      switch(entityType) {
      case INSTANCE:
         rangerAccessResource.setValue("instance", ((InstanceId)entityId).getInstance());
         break;
      case NAMESPACE:
         this.setAccessResource(new InstanceId(this.instanceName), rangerAccessResource);
         rangerAccessResource.setValue("namespace", ((NamespaceId)entityId).getNamespace());
         break;
      case ARTIFACT:
         ArtifactId artifactId = (ArtifactId)entityId;
         this.setAccessResource(artifactId.getParent(), rangerAccessResource);
         rangerAccessResource.setValue("artifact", artifactId.getArtifact());
         break;
      case APPLICATION:
         ApplicationId applicationId = (ApplicationId)entityId;
         this.setAccessResource(applicationId.getParent(), rangerAccessResource);
         rangerAccessResource.setValue("application", applicationId.getApplication());
         break;
      case DATASET:
         DatasetId dataset = (DatasetId)entityId;
         this.setAccessResource(dataset.getParent(), rangerAccessResource);
         rangerAccessResource.setValue("dataset", dataset.getDataset());
         break;
      case DATASET_MODULE:
         DatasetModuleId datasetModuleId = (DatasetModuleId)entityId;
         this.setAccessResource(datasetModuleId.getParent(), rangerAccessResource);
         rangerAccessResource.setValue("dataset_module", datasetModuleId.getModule());
         break;
      case DATASET_TYPE:
         DatasetTypeId datasetTypeId = (DatasetTypeId)entityId;
         this.setAccessResource(datasetTypeId.getParent(), rangerAccessResource);
         rangerAccessResource.setValue("dataset_type", datasetTypeId.getType());
         break;
      case STREAM:
         StreamId streamId = (StreamId)entityId;
         this.setAccessResource(streamId.getParent(), rangerAccessResource);
         rangerAccessResource.setValue("stream", streamId.getStream());
         break;
      case PROGRAM:
         ProgramId programId = (ProgramId)entityId;
         this.setAccessResource(programId.getParent(), rangerAccessResource);
         rangerAccessResource.setValue("program", programId.getType().getPrettyName().toLowerCase() + "." + programId.getProgram());
         break;
      case SECUREKEY:
         SecureKeyId secureKeyId = (SecureKeyId)entityId;
         this.setAccessResource(secureKeyId.getParent(), rangerAccessResource);
         rangerAccessResource.setValue("secure_key", secureKeyId.getName());
         break;
      case KERBEROSPRINCIPAL:
         this.setAccessResource(new InstanceId(this.instanceName), rangerAccessResource);
         rangerAccessResource.setValue("principal", ((KerberosPrincipalId)entityId).getPrincipal());
         break;
      default:
         throw new IllegalArgumentException(String.format("The entity %s is of unknown type %s", entityId, entityType));
      }

   }
}
