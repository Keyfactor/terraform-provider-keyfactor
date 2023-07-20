package keyfactor

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"strconv"
)

type dataSourceCertificateStoreType struct{}

func (r dataSourceCertificateStoreType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"container_id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Container identifier of the store's associated certificate store container.",
			},
			"client_machine": {
				Type: types.StringType,
				//Computed:    true,
				Required:    true,
				Description: "Client machine name; value depends on certificate store type. See API reference guide",
			},
			"store_path": {
				Type: types.StringType,
				//Computed:    true,
				Required:    true,
				Description: "Path to the new certificate store on a target. Format varies depending on type.",
			},
			"store_type": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Short name of certificate store type. See API reference guide",
			},
			"approved": {
				Type:     types.BoolType,
				Optional: true,
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},
				Description: "Bool that indicates the approval status of store created. Default is true, omit if unsure.",
			},
			"create_if_missing": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "Bool that indicates if the store should be created with information provided. Valid only for JKS type, omit if unsure.",
			},
			"properties": {
				Type:        types.MapType{ElemType: types.StringType},
				Optional:    true,
				Description: "Properties specific to certificate store type configured as key-value pairs.",
			},
			"agent_id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "String indicating the Keyfactor Command GUID of the orchestrator for the created store.",
			},
			"agent_assigned": {
				Type:     types.BoolType,
				Optional: true,
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},
				Description: "Bool indicating if there is an orchestrator assigned to the new certificate store.",
			},
			"container_name": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Name of certificate store's associated container, if applicable.",
			},
			"inventory_schedule": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Inventory schedule for new certificate store.",
			},
			"set_new_password_allowed": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "Indicates whether the store password can be changed.",
			},
			"password": {
				Type:        types.StringType,
				Computed:    true,
				Sensitive:   true,
				Description: "The StorePassword field for a certificate store. This is only set if store requires password.",
			},
			"id": {
				Type: types.StringType,
				//Required:    true,
				Computed:    true,
				Description: "Keyfactor certificate store GUID.",
			},
		},
	}, nil
}

func (r dataSourceCertificateStoreType) NewDataSource(ctx context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceCertificateStore{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceCertificateStore struct {
	p provider
}

func (r dataSourceCertificateStore) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	var state CertificateStore

	tflog.Info(ctx, "Read called on certificate resource")
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on certificate store resource")
	//certificateStoreID := state.ID.Value
	clientMachine := state.ClientMachine.Value
	storePath := state.StorePath.Value
	containerID := state.ContainerID.Value

	//tflog.SetField(ctx, "certificate_id", certificateStoreID)
	tflog.SetField(ctx, "client_machine", clientMachine)
	tflog.SetField(ctx, "store_path", storePath)

	//sResp, err := r.p.client.GetCertificateStoreByID(certificateStoreID)
	sRespList, err := r.p.client.GetCertificateStoreByClientAndStorePath(clientMachine, storePath, containerID)
	if err != nil {
		response.Diagnostics.AddError(
			"Error reading certificate store",
			"Error reading certificate store: %s"+err.Error(),
		)
		return
	}

	if len(*sRespList) == 0 {
		response.Diagnostics.AddError(
			"Error reading certificate store",
			"Error reading certificate store: %s"+err.Error(),
		)
		return
	}
	sRespRef := *sRespList
	//Because we're looking up by client machine and store path, there should only be one result as that's what Command uses for uniqueness as of KF 9.x
	sResp := sRespRef[0]

	password := state.Password.Value
	tflog.Trace(ctx, fmt.Sprintf("Password for store %s: %s", sResp.Id, password))

	if err != nil {
		response.Diagnostics.AddError(
			"Certificate store not found",
			fmt.Sprintf("Unable to locate certificate store using client machine '%s' and storepath '%s' %s", clientMachine, storePath, err.Error()),
		)
		return
	}

	propElems := make(map[string]attr.Value)
	propsObj := make(map[string]interface{})
	if sResp.PropertiesString != "" {
		//convert JSON string to map
		unescapedJSON, _ := unescapeJSON(sResp.PropertiesString)
		jsonErr := json.Unmarshal(unescapedJSON, &propsObj)
		if jsonErr != nil {
			response.Diagnostics.AddError(
				"Error reading certificate store",
				"Error reading certificate store: %s"+jsonErr.Error(),
			)
			return
		}
	}
	for k, v := range propsObj {
		propElems[k] = types.String{Value: v.(string)}
	}
	var result = CertificateStore{
		ID:                    types.String{Value: sResp.Id},
		ContainerID:           types.Int64{Value: int64(sResp.ContainerId)},
		ContainerName:         types.String{Value: sResp.ContainerName},
		AgentId:               types.String{Value: sResp.AgentId},
		AgentAssigned:         types.Bool{Value: sResp.AgentAssigned},
		ClientMachine:         state.ClientMachine,
		StorePath:             state.StorePath,
		StoreType:             types.String{Value: fmt.Sprintf("%v", sResp.CertStoreType)},
		Approved:              types.Bool{Value: sResp.Approved},
		CreateIfMissing:       types.Bool{Value: sResp.CreateIfMissing},
		Properties:            types.Map{ElemType: types.StringType, Elems: propElems},
		Password:              types.String{Value: ""},
		SetNewPasswordAllowed: types.Bool{Value: sResp.SetNewPasswordAllowed},
		InventorySchedule:     state.InventorySchedule,
	}

	// Set state
	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func unescapeJSON(jsonData string) ([]byte, error) {
	unescapedJSON, err := strconv.Unquote(jsonData)
	if err != nil {
		return []byte(jsonData), err
	}
	return []byte(unescapedJSON), nil
}
