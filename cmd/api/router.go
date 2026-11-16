package main

import "net/http"

func newRouter(api *API) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", api.health)
	mux.HandleFunc("POST /v1/auth/register", api.register)
	mux.HandleFunc("POST /v1/auth/login", api.login)

	mux.HandleFunc("GET /v1/me", api.me)
	mux.HandleFunc("POST /v1/me/password", api.changeMyPassword)
	mux.HandleFunc("POST /v1/me/sessions/revoke", api.revokeMySessions)
	mux.HandleFunc("GET /v1/me/subscription", api.getMySubscription)
	mux.HandleFunc("GET /v1/me/subscriptions", api.listMySubscriptions)

	mux.HandleFunc("GET /v1/devices", api.listDevices)
	mux.HandleFunc("POST /v1/devices", api.createDevice)
	mux.HandleFunc("PATCH /v1/devices/{id}", api.renameMyDevice)
	mux.HandleFunc("DELETE /v1/devices/{id}", api.revokeDevice)

	mux.HandleFunc("GET /v1/admin/users", api.adminListUsers)
	mux.HandleFunc("PATCH /v1/admin/users/{id}/status", api.adminSetUserStatus)
	mux.HandleFunc("GET /v1/admin/plans", api.adminListPlans)
	mux.HandleFunc("POST /v1/admin/plans", api.adminCreatePlan)
	mux.HandleFunc("PATCH /v1/admin/plans/{id}/status", api.adminSetPlanStatus)
	mux.HandleFunc("POST /v1/admin/users/{id}/subscriptions", api.adminCreateSubscription)
	mux.HandleFunc("GET /v1/admin/subscriptions", api.adminListSubscriptions)
	mux.HandleFunc("POST /v1/admin/subscriptions/{id}/cancel", api.adminCancelSubscription)
	mux.HandleFunc("GET /v1/admin/audit-logs", api.adminListAuditLogs)
	mux.HandleFunc("GET /v1/admin/invites", api.adminListInvites)
	mux.HandleFunc("POST /v1/admin/invites", api.adminCreateInvite)
	mux.HandleFunc("DELETE /v1/admin/invites/{id}", api.adminRevokeInvite)
	mux.HandleFunc("GET /v1/admin/users/{id}/devices", api.adminListUserDevices)
	mux.HandleFunc("DELETE /v1/admin/users/{id}/devices/{deviceID}", api.adminRevokeUserDevice)
	mux.HandleFunc("PUT /v1/admin/devices/{id}/assignment", api.adminAssignDeviceToNode)
	mux.HandleFunc("DELETE /v1/admin/devices/{id}/assignment", api.adminUnassignDeviceFromNode)
	mux.HandleFunc("GET /v1/admin/nodes", api.adminListNodes)
	mux.HandleFunc("POST /v1/admin/nodes", api.adminCreateNode)
	mux.HandleFunc("PATCH /v1/admin/nodes/{id}", api.adminUpdateNode)
	mux.HandleFunc("PATCH /v1/admin/nodes/{id}/status", api.adminSetNodeStatus)
	mux.HandleFunc("POST /v1/admin/nodes/{id}/credentials/rotate", api.adminRotateNodeCredential)
	mux.HandleFunc("DELETE /v1/admin/nodes/{id}/credentials", api.adminRevokeNodeCredential)
	mux.HandleFunc("POST /v1/node/heartbeat", api.nodeHeartbeat)
	mux.HandleFunc("GET /v1/node/config", api.nodeConfig)
	mux.HandleFunc("POST /v1/node/config/ack", api.acknowledgeNodeConfig)

	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusTemporaryRedirect)
	})
	mux.Handle("GET /admin/", http.StripPrefix("/admin/", adminUIHandler()))

	return apiMiddleware(mux)
}
