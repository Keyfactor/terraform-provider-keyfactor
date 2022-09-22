package keyfactor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"time"
)

type resourceKeyfactorCertificateDeploymentType struct{}

func (r resourceKeyfactorCertificateDeploymentType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A unique identifier for this certificate deployment.",
			},
			"certificate_id": {
				Type:          types.Int64Type,
				Required:      true,
				Description:   "Keyfactor certificate ID",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"certificate_store_id": {
				Type:          types.StringType,
				Required:      true,
				Description:   "A string containing the GUID for the certificate store to which the certificate should be added.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"certificate_alias": {
				Type:          types.StringType,
				Required:      true,
				Description:   "A string providing an alias to be used for the certificate upon entry into the certificate store. The function of the alias varies depending on the certificate store type. Please ensure that the alias is lowercase, or problems can arise in Terraform Plan.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"key_password": {
				Type:          types.StringType,
				Optional:      true,
				Sensitive:     true,
				Description:   "Password that protects PFX certificate, if the certificate was enrolled using PFX enrollment, or is password protected in general. This value cannot change, and Terraform will throw an error if a change is attempted.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
		},
	}, nil
}

func (r resourceKeyfactorCertificateDeploymentType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceKeyfactorCertificateDeployment{
		p: *(p.(*provider)),
	}, nil
}

type resourceKeyfactorCertificateDeployment struct {
	p provider
}

func (r resourceKeyfactorCertificateDeployment) Create(ctx context.Context, request tfsdk.CreateResourceRequest, response *tfsdk.CreateResourceResponse) {
	if !r.p.configured {
		response.Diagnostics.AddError(
			"Provider not configured",
			"The provider hasn't been configured before apply, likely because it depends on an unknown value from another resource. This leads to weird stuff happening, so we'd prefer if you didn't do that. Thanks!",
		)
		return
	}

	// Retrieve values from plan
	var plan KeyfactorCertificateDeployment
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan

	kfClient := r.p.client

	certificateId := plan.CertificateId.Value
	certificateIdInt := int(certificateId)
	storeId := plan.StoreId.Value
	certificateAlias := plan.CertificateAlias.Value
	keyPassword := plan.KeyPassword.Value
	hid := fmt.Sprintf("%v-%s-%s", certificateId, storeId, certificateAlias)

	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	ctx = tflog.SetField(ctx, "certificate_store_id", storeId)
	ctx = tflog.SetField(ctx, "certificate_alias", certificateAlias)
	tflog.Info(ctx, "Create called on certificate deployment resource")

	//sans := plan.SANs
	//metadata := plan.Metadata.Elems
	addErr := addCertificateToStore(ctx, kfClient, certificateIdInt, certificateAlias, keyPassword, storeId)
	if addErr != nil {
		response.Diagnostics.AddError(
			"Certificate deployment error",
			fmt.Sprintf("Unknown error during deploy of certificate '%v'(%s) to store '%s': "+addErr.Error(), certificateId, certificateAlias, storeId),
		)
	}
	if response.Diagnostics.HasError() {
		return
	}

	vErr := validateCertificatesInStore(ctx, kfClient, certificateIdInt, storeId)
	if vErr != nil {
		response.Diagnostics.AddError(
			"Deployment validation error.",
			fmt.Sprintf("Unknown error during validation of deploy of certificate '%s' to store '%s (%s)': "+vErr.Error(), certificateId, storeId, certificateAlias),
		)
	}
	if response.Diagnostics.HasError() {
		return
	}

	// Set state
	var result = KeyfactorCertificateDeployment{
		ID:               types.String{Value: fmt.Sprintf("%x", sha256.Sum256([]byte(hid)))},
		CertificateId:    plan.CertificateId,
		StoreId:          plan.StoreId,
		CertificateAlias: plan.CertificateAlias,
		KeyPassword:      plan.KeyPassword,
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

}

func (r resourceKeyfactorCertificateDeployment) Read(ctx context.Context, request tfsdk.ReadResourceRequest, response *tfsdk.ReadResourceResponse) {
	var state KeyfactorCertificateDeployment
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	kfClient := r.p.client

	certificateId := state.CertificateId.Value
	certificateIdInt := int(certificateId)
	storeId := state.StoreId.Value
	//storeIdInt := int(storeId)
	certificateAlias := state.CertificateAlias.Value
	//keyPassword := state.KeyPassword.Value
	//hid := fmt.Sprintf("%s-%s-%s", certificateId, storeId, certificateAlias)

	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	ctx = tflog.SetField(ctx, "certificate_store_id", storeId)
	ctx = tflog.SetField(ctx, "certificate_alias", certificateAlias)
	tflog.Info(ctx, "Create called on certificate deployment resource")

	// Get certificate context
	args := &api.GetCertificateContextArgs{
		IncludeLocations: boolToPointer(true),
		Id:               certificateIdInt,
	}
	certificateData, err := kfClient.GetCertificateContext(args)
	if err != nil {
		response.Diagnostics.AddError(
			"Deployment read error.",
			fmt.Sprintf("Unknown error during read status of deployment of certificate '%s' to store '%s (%s)': "+err.Error(), certificateId, storeId, certificateAlias),
		)
	}
	locations := certificateData.Locations
	for _, location := range locations {
		tflog.Debug(ctx, fmt.Sprintf("Certificate %v stored in location: %v", certificateIdInt, location))
	}

	// Set state
	var result = KeyfactorCertificateDeployment{
		ID:               state.ID,
		CertificateId:    state.CertificateId,
		StoreId:          state.StoreId,
		CertificateAlias: state.CertificateAlias,
		KeyPassword:      state.KeyPassword,
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceKeyfactorCertificateDeployment) Update(ctx context.Context, request tfsdk.UpdateResourceRequest, response *tfsdk.UpdateResourceResponse) {
	// Get plan values
	var plan KeyfactorCertificate
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get current state
	var state KeyfactorCertificate
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// API Actions

	// Set state
	tflog.Error(ctx, "Update called on certificate deployment resource")
	response.Diagnostics.AddError(
		"Certificate deployment updates not implemented.",
		fmt.Sprintf("Error, only create and delete actions are supported for certificate deployments."),
	)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceKeyfactorCertificateDeployment) Delete(ctx context.Context, request tfsdk.DeleteResourceRequest, response *tfsdk.DeleteResourceResponse) {
	var state KeyfactorCertificateDeployment
	diags := request.State.Get(ctx, &state)

	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Vars and logging contexts
	kfClient := r.p.client

	certificateId := state.CertificateId.Value
	//certificateIdInt := int(certificateId)
	storeId := state.StoreId.Value
	//storeIdInt := int(storeId)
	certificateAlias := state.CertificateAlias.Value
	//keyPassword := state.KeyPassword.Value
	//hid := fmt.Sprintf("%s-%s-%s", certificateId, storeId, certificateAlias)

	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	ctx = tflog.SetField(ctx, "certificate_store_id", storeId)
	ctx = tflog.SetField(ctx, "certificate_alias", certificateAlias)
	tflog.Info(ctx, "Create called on certificate deployment resource")

	// Remove certificate from store
	var diff []api.CertificateStore
	certStoreRequest := api.CertificateStore{
		CertificateStoreId: storeId,
		Alias:              certificateAlias,
	}
	diff = append(diff, certStoreRequest)

	// Remove resource from state
	err := removeCertificateAliasFromStore(ctx, kfClient, &diff)
	if err != nil {
		response.Diagnostics.AddError(
			"Certificate deployment error",
			fmt.Sprintf("Unknown error during removal of certificate '%s' from store '%s (%s)': "+err.Error(), certificateId, storeId, certificateAlias),
		)
	}

	if response.Diagnostics.HasError() {
		return
	}
	response.State.RemoveResource(ctx)
}

func (r resourceKeyfactorCertificateDeployment) ImportState(ctx context.Context, request tfsdk.ImportResourceStateRequest, response *tfsdk.ImportResourceStateResponse) {
	tflog.Error(ctx, "Import called on certificate deployment resource")
	response.Diagnostics.AddError(
		"Certificate deployment imports not implemented.",
		fmt.Sprintf("Error, only create and delete actions are supported for certificate deployments."),
	)
	if response.Diagnostics.HasError() {
		return
	}
}

//func setCertificatesInStore(ctx context.Context, conn *api.Client, certificateId int, keyPassword string, storeId int, storeAlias string) error {
//
//	tflog.Debug(ctx, fmt.Sprintf("Setting certificate %v in Keyfactor store %v", certificateId, storeId))
//	// First, blindly add the certificate to each of the certificate storeId found in storeList.
//	err := addCertificateToStore(conn, certificateId, keyPassword, storeId, storeAlias)
//	if err != nil {
//		return err
//	}
//
//	// Then, compile a list of storeId that the certificate is found in, and figure out the delta
//	args := &api.GetCertificateContextArgs{
//		IncludeLocations: boolToPointer(true),
//		Id:               certificateId,
//	}
//	certificateData, err := conn.GetCertificateContext(args)
//	if err != nil {
//		return err
//	}
//	locations := certificateData.Locations
//	expectedStores := make([]string, len(storeId))
//
//	// Want to find the elements in locations that are not in storeId
//	// We also want to retain the alias
//	list := make(map[string]struct{}, len(storeId))
//	for i, x := range storeId {
//		j := x.(map[string]interface{})
//
//		storeId := j["certificate_store_id"].(string)
//		list[storeId] = struct{}{}
//
//		// Since we're already looping through the store IDs, place them in a more readable data structre for later use
//		expectedStores[i] = storeId
//	}
//
//	// The elements of diff should be removed
//	// Also, removing a certificate from a certificate store implies that the certificate is currently in the store.
//	var diff []api.CertificateStore
//	for _, x := range locations {
//		if _, found := list[x.CertStoreId]; !found {
//			temp := api.CertificateStore{
//				CertificateStoreId: x.CertStoreId,
//				Alias:              x.Alias,
//			}
//			diff = append(diff, temp)
//		}
//	}
//
//	if len(diff) > 0 {
//		err = removeCertificateAliasFromStore(conn, &diff)
//		if err != nil {
//			return err
//		}
//	}
//
//	// Finally, Keyfactor tends to take a hot second to enact these changes despite being told to make them immediately.
//	// Block for a long time until the changes are validated.
//	err = validateCertificatesInStore(conn, expectedStores, certificateId)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

// addCertificateToStore adds certificate certId to each of the stores configured by stores. Note that stores is a list of
// map[string]interface{} and contains the required configuration for api.AddCertificateToStores().
func addCertificateToStore(ctx context.Context, conn *api.Client, certificateId int, certificateAlias string, keyPassword string, storeId string) error {
	var storesStruct []api.CertificateStore

	storeRequest := new(api.CertificateStore)

	storeRequest.CertificateStoreId = storeId
	storeRequest.Alias = certificateAlias

	storeRequest.IncludePrivateKey = true //todo: make this configurable
	storeRequest.Overwrite = true
	storeRequest.PfxPassword = keyPassword
	storesStruct = append(storesStruct, *storeRequest)

	// We want Keyfactor to immediately apply these changes.
	tflog.Debug(ctx, "Creating immediate request to add certificate to store")
	schedule := &api.InventorySchedule{
		Immediate: boolToPointer(true),
	}
	config := &api.AddCertificateToStore{
		CertificateId:     certificateId,
		CertificateStores: &storesStruct,
		InventorySchedule: schedule,
	}
	tflog.Debug(ctx, fmt.Sprintf("Adding certificate %v to Keyfactor store %v", certificateId, storeId))
	_, err := conn.AddCertificateToStores(config)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("Error adding certificate %v to Keyfactor store %v: %v", certificateId, storeId, err))
		return err
	}
	tflog.Debug(ctx, fmt.Sprintf("Successfully added certificate %v to Keyfactor store %v", certificateId, storeId))
	return nil
}

func validateCertificatesInStore(ctx context.Context, conn *api.Client, certificateId int, storeId string) error {
	valid := false
	tflog.Debug(ctx, fmt.Sprintf("Validating certificate %v is in Keyfactor store %v", certificateId, storeId))
	retry_delay := 2
	for i := 0; i < 5; i++ {
		args := &api.GetCertificateContextArgs{
			IncludeLocations: boolToPointer(true),
			Id:               certificateId,
		}
		certificateData, err := conn.GetCertificateContext(args)
		if err != nil {
			return err
		}
		storeList := make([]string, len(certificateData.Locations))
		for j, store := range certificateData.Locations {
			storeList[j] = store.CertStoreId
		}

		//if len(findStringDifference(certificateStores, storeList)) == 0 && len(findStringDifference(storeList, certificateStores)) == 0 {
		//	valid = true
		//	break
		//}
		retry_delay = retry_delay * (i + 1)
		tflog.Debug(ctx, fmt.Sprintf("Certificate %v not found in Keyfactor store %v. Retrying in %v seconds", certificateId, storeId, retry_delay))
		time.Sleep(time.Duration(retry_delay) * time.Second)
	}
	if !valid {
		return fmt.Errorf("validateCertificatesInStore timed out. certificate could deploy eventually, but terraform change operation will fail. run terraform plan later to verify that the certificate was deployed successfully")
	}
	return nil
}

func removeCertificateAliasFromStore(ctx context.Context, conn *api.Client, certificateStores *[]api.CertificateStore) error {
	// We want Keyfactor to immediately apply these changes.
	schedule := &api.InventorySchedule{
		Immediate: boolToPointer(true),
	}
	config := &api.RemoveCertificateFromStore{
		CertificateStores: certificateStores,
		InventorySchedule: schedule,
	}

	_, err := conn.RemoveCertificateFromStores(config)
	if err != nil {
		return err
	}

	return nil
}
