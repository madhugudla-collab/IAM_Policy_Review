from urllib import response

import boto3
import json

class IAM_Policy_Auditor_class:
    def __init__(self):
        self.iam_client = boto3.client('iam')
        self.sts_client = boto3.client('sts')

    
    def iam_policy_auditor(self, role_name):
        print(f"\nAuditing policies for IAM role: '{role_name}'")
        try:
  #          print("DEBUG: Calling list_attached_role_policies...")
            response = self.iam_client.list_attached_role_policies(RoleName=role_name)
  #          print("DEBUG: Full response from AWS:")
  #          print(json.dumps(response, indent=2, default=str))

            attached_policies = response.get('AttachedPolicies', [])

            if not attached_policies:
                print("\nResult: No policies are attached to this role.")
                return

            print("\nAttached Policies:")
            for policy in attached_policies:
                policy_name = policy.get('PolicyName')
                policy_arn = policy.get('PolicyArn')
                print(f"- {policy_name}: {policy_arn}")
                self.Privilege_policy_verify(policy_arn, role_name)       

        except self.iam_client.exceptions.NoSuchEntityException:
            print(f"ERROR: The role '{role_name}' does not exist.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def Privilege_policy_verify(self, policy_arn, role_name):
        try:
            #print("privilege policy review initiated .\n")
            policy_name = self.iam_client.get_policy(PolicyArn=policy_arn)['Policy']['PolicyName']
            print(f"policy name is {policy_name}")

            # 1. Get the Policy metadata to find the DefaultVersionId
            policy_info = self.iam_client.get_policy(PolicyArn=policy_arn)
            version_id = policy_info['Policy']['DefaultVersionId']
          
            # 2. Get the actual JSON document using the VersionId
            response = self.iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id
            )
            # 3. Access the Document (Correct Key Path)
            policy_doc = response['PolicyVersion']['Document']
            #print(json.dumps(policy_doc, indent=2, default=str))

            # Verify the policy name itself called it as a 'Administrator Accss or not'
            #print(f"analzing statement...... BEFORE FOR LOOP\n")
            if policy_doc.get('PolicyName') == 'AdministratorAccess' or policy_doc.get('PolicyName') == 'Admin':
                print(f"role Name {role_name}...ALERT: This role has the 'AdministratorAccess' policy attached, which grants full access")
    
            for stmt in policy_doc.get("Statement", []):
                effect = stmt.get("Effect")
      # Check Actions (Standardize to list)
                actions = stmt.get("Action", [])
                if isinstance(actions, str): 
                    actions = [actions]

                
                # Check Resources (Standardize to list)
                resources = stmt.get("Resource", [])
                if isinstance(resources, str): 
                    resources = [resources]

                if effect == "Allow":
                     # Ensure that actions are least privileged
                    if "*" in actions:
                        print(f"ALERT: Privilege access violation detected in Actions!")
                        print(f"Role Name:           {role_name}")
                        print(f"Policy Name:         {policy_name}") 
                        print(f"Policy ARN:          {policy_arn}")
                        print(f"Violation:           '*' identified in Actions section")
                        print("-" * 60)
                        print("Recommended Solution:")
                        print("-" * 60)
                        print(" Follow the principle of least privilege and restrict access to only required Services Actions.")
                        print(" If you have a valid business justification, please reach out to your Security/AppSec Engineer for review.")
                        print("-" * 60 + "\n")
                # Ensure that Resources are not overly permissive
                    if "*" in resources:
                        print(f"ALERT: Privilege access violation detected!")
                        print(f"Role Name:           {role_name}")
                        print(f"Policy Name:         {policy_name}") 
                        print(f"Policy ARN:          {policy_arn}")
                        print(f"Violation:           '*' identified in Resource section")
                        print("-" * 60)
                        print("Recommended Solution:")
                        print("-" * 60)
                        print(" Follow the principle of least privilege and restrict access to only required resources.")
                        print(" If you have a valid business justification, please reach out to your Security/AppSec Engineer for review.")
                        print("-" * 60 + "\n")

                    if "iam:PassRole" in actions:
                        print(f"ALERT: Privilege access violation detected  IAM pass role detected in Actions section!")
                        print(f"Role Name:           {role_name}")
                        print(f"Policy Name:         {policy_name}") 
                        print(f"Policy ARN:          {policy_arn}")
                        print(f"Violation:           'passrole' identified in Resource section")
                        print("-" * 60)
                        print("Recommended Solution:")
                        print("-" * 60)
                        print(" Follow the principle of least privilege and restrict access to only required resources.")
                        print(" If you have a valid business justification, please reach out to your Security/AppSec Engineer for review.")
                        print("-" * 60 + "\n")


                                                  
        except Exception as e:
                print(f"unexpected error document {e}")

                return
        

    def verify_account_access(self, target_account_id):
        """
        Verifies if the current AWS session matches the target Account ID.
        """
        try:
            # Use STS to find out 'who' the current session is
            identity = self.sts_client.get_caller_identity()
            current_id = identity['Account']
            
            if current_id == target_account_id:
                print(f" Access Verified: Connected to Account {current_id}")
                return True
            else:
                print(f" MISMATCH: You are logged into {current_id}, "
                      f"but you entered {target_account_id}.")
                return False
        except Exception as e:
            print(f"Verification Error: {e}")
            return False
    
    def list_all_roles(self):
        """
        Fetches IAM roles in the account (up to 1,000 roles).
        """
        try:
            # list_roles returns a dictionary containing 'Roles' and 'IsTruncated'
            response = self.iam_client.list_roles(MaxItems=1000)
            return response.get('Roles', [])
        except Exception as e:
            print(f"Error listing roles: {e}")
            return []


        



if __name__ == "__main__":
    policy_audit = IAM_Policy_Auditor_class()
      
    try:
        print(f"IAM policy Auditor Please choose the peferred options")
        print("1. Scan all account policies")
        print("2. Scan a specific IAM role")
        user_input = input("Enter option (1 or 2): ").strip()
        
        if user_input == "2":
            role_name_input = input("Enter the IAM role name to audit: ").strip()
            if role_name_input:
                policy_audit.iam_policy_auditor(role_name_input)
            else:
                print("Invalidrole name entered. Skipping policy audit, Please try again with a valid role name.")
        else:       
            print("No role name entered. Skipping policy audit.")
        
        if user_input == "1":
           entered_id = input("Enter the AWS Account ID to confirm before scanning all policies: ").strip() 
           if policy_audit.verify_account_access(entered_id):
                print(f"Starting full scan for account {entered_id}...")
                for role in policy_audit.list_all_roles():
                    policy_audit.iam_policy_auditor(role['RoleName'])
        else:
                print("Scan aborted: Account ID mismatch.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
