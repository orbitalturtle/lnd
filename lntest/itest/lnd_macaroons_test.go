package itest

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/macaroon.v2"
)

// testMacaroonAuthentication makes sure that if macaroon authentication is
// enabled on the gRPC interface, no requests with missing or invalid
// macaroons are allowed. Further, the specific access rights (read/write,
// entity based) and first-party caveats are tested as well.
func testMacaroonAuthentication(net *lntest.NetworkHarness, ht *harnessTest) {
	var (
		infoReq    = &lnrpc.GetInfoRequest{}
		newAddrReq = &lnrpc.NewAddressRequest{
			Type: AddrTypeWitnessPubkeyHash,
		}
		testNode = net.Alice
	)

	testCases := []struct {
		name string
		run  func(ctxt context.Context, t *testing.T)
	}{{
		// First test: Make sure we get an error if we use no macaroons
		// but try to connect to a node that has macaroon authentication
		// enabled.
		name: "no macaroon",
		run: func(ctxt context.Context, t *testing.T) {
			conn, err := testNode.ConnectRPC(false)
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()
			client := lnrpc.NewLightningClient(conn)
			_, err = client.GetInfo(ctxt, infoReq)
			require.Error(t, err)
			require.Contains(t, err.Error(), "expected 1 macaroon")
		},
	}, {
		// Second test: Ensure that an invalid macaroon also triggers an
		// error.
		name: "invalid macaroon",
		run: func(ctxt context.Context, t *testing.T) {
			invalidMac, _ := macaroon.New(
				[]byte("dummy_root_key"), []byte("0"), "itest",
				macaroon.LatestVersion,
			)
			cleanup, client := macaroonClient(
				t, testNode, invalidMac,
			)
			defer cleanup()
			_, err := client.GetInfo(ctxt, infoReq)
			require.Error(t, err)
			require.Contains(t, err.Error(), "cannot get macaroon")
		},
	}, {
		// Third test: Try to access a write method with read-only
		// macaroon.
		name: "read only macaroon",
		run: func(ctxt context.Context, t *testing.T) {
			readonlyMac, err := testNode.ReadMacaroon(
				testNode.ReadMacPath(), defaultTimeout,
			)
			require.NoError(t, err)
			cleanup, client := macaroonClient(
				t, testNode, readonlyMac,
			)
			defer cleanup()
			_, err = client.NewAddress(ctxt, newAddrReq)
			require.Error(t, err)
			require.Contains(t, err.Error(), "permission denied")
		},
	}, {
		// Fourth test: Check first-party caveat with timeout that
		// expired 30 seconds ago.
		name: "expired macaroon",
		run: func(ctxt context.Context, t *testing.T) {
			readonlyMac, err := testNode.ReadMacaroon(
				testNode.ReadMacPath(), defaultTimeout,
			)
			require.NoError(t, err)
			timeoutMac, err := macaroons.AddConstraints(
				readonlyMac, macaroons.TimeoutConstraint(-30),
			)
			require.NoError(t, err)
			cleanup, client := macaroonClient(
				t, testNode, timeoutMac,
			)
			defer cleanup()
			_, err = client.GetInfo(ctxt, infoReq)
			require.Error(t, err)
			require.Contains(t, err.Error(), "macaroon has expired")
		},
	}, {
		// Fifth test: Check first-party caveat with invalid IP address.
		name: "invalid IP macaroon",
		run: func(ctxt context.Context, t *testing.T) {
			readonlyMac, err := testNode.ReadMacaroon(
				testNode.ReadMacPath(), defaultTimeout,
			)
			require.NoError(t, err)
			invalidIPAddrMac, err := macaroons.AddConstraints(
				readonlyMac, macaroons.IPLockConstraint(
					"1.1.1.1",
				),
			)
			require.NoError(t, err)
			cleanup, client := macaroonClient(
				t, testNode, invalidIPAddrMac,
			)
			defer cleanup()
			_, err = client.GetInfo(ctxt, infoReq)
			require.Error(t, err)
			require.Contains(t, err.Error(), "different IP address")
		},
	}, {
		// Sixth test: Make sure that if we do everything correct and
		// send the admin macaroon with first-party caveats that we can
		// satisfy, we get a correct answer.
		name: "correct macaroon",
		run: func(ctxt context.Context, t *testing.T) {
			adminMac, err := testNode.ReadMacaroon(
				testNode.AdminMacPath(), defaultTimeout,
			)
			require.NoError(t, err)
			adminMac, err = macaroons.AddConstraints(
				adminMac, macaroons.TimeoutConstraint(30),
				macaroons.IPLockConstraint("127.0.0.1"),
			)
			require.NoError(t, err)
			cleanup, client := macaroonClient(t, testNode, adminMac)
			defer cleanup()
			res, err := client.NewAddress(ctxt, newAddrReq)
			require.NoError(t, err, "get new address")
			assert.Contains(t, res.Address, "bcrt1")
		},
	}, {
		// Seventh test: Bake a macaroon that can only access exactly
		// two RPCs and make sure it works as expected.
		name: "custom URI permissions",
		run: func(ctxt context.Context, t *testing.T) {
			entity := macaroons.PermissionEntityCustomURI
			req := &lnrpc.BakeMacaroonRequest{
				Permissions: []*lnrpc.MacaroonPermission{{
					Entity: entity,
					Action: "/lnrpc.Lightning/GetInfo",
				}, {
					Entity: entity,
					Action: "/lnrpc.Lightning/List" +
						"Permissions",
				}},
			}
			bakeRes, err := testNode.BakeMacaroon(ctxt, req)
			require.NoError(t, err)

			// Create a connection that uses the custom macaroon.
			customMacBytes, err := hex.DecodeString(
				bakeRes.Macaroon,
			)
			require.NoError(t, err)
			customMac := &macaroon.Macaroon{}
			err = customMac.UnmarshalBinary(customMacBytes)
			require.NoError(t, err)
			cleanup, client := macaroonClient(
				t, testNode, customMac,
			)
			defer cleanup()

			// Call GetInfo which should succeed.
			_, err = client.GetInfo(ctxt, infoReq)
			require.NoError(t, err)

			// Call ListPermissions which should also succeed.
			permReq := &lnrpc.ListPermissionsRequest{}
			permRes, err := client.ListPermissions(ctxt, permReq)
			require.NoError(t, err)
			require.Greater(
				t, len(permRes.MethodPermissions), 10,
				"permissions",
			)

			// Try NewAddress which should be denied.
			_, err = client.NewAddress(ctxt, newAddrReq)
			require.Error(t, err)
			require.Contains(t, err.Error(), "permission denied")
		},
	}, {
		// Eighth test: check that with the CheckMacaroonPermissions
		// RPC, we can check that a macaroon follows constraints,
		// without looking at permissions LND is not familiar with.
		name: "check macaroon without knowing permissions",
		run: func(ctxt context.Context, t *testing.T) {

			// A test macaroon created with combined permissions
			// from LND and daemons from outside LND -- pool, loop,
			// and faraday.
			macStr := "0201036c6e6402f003030a10a0565043f79d" +
				"a76d439e740fc0be27fe1201301a160a076163636f75" +
				"6e74120472656164120577726974651a160a07616464" +
				"72657373120472656164120577726974651a0f0a0761" +
				"756374696f6e1204726561641a0d0a05617564697412" +
				"04726561641a0c0a04617574681204726561641a130a" +
				"04696e666f120472656164120577726974651a100a08" +
				"696e7369676874731204726561641a170a08696e766f" +
				"69636573120472656164120577726974651a0f0a046c" +
				"6f6f701202696e12036f75741a210a086d616361726f" +
				"6f6e120867656e657261746512047265616412057772" +
				"6974651a160a076d6573736167651204726561641205" +
				"77726974651a170a086f6666636861696e1204726561" +
				"64120577726974651a160a076f6e636861696e120472" +
				"656164120577726974651a140a056f72646572120472" +
				"656164120577726974651a140a057065657273120472" +
				"656164120577726974651a0d0a057261746573120472" +
				"6561641a160a0e7265636f6d6d656e646174696f6e12" +
				"04726561641a0e0a067265706f72741204726561641a" +
				"180a067369676e6572120867656e6572617465120472" +
				"6561641a1a0a0b73756767657374696f6e7312047265" +
				"6164120577726974651a150a04737761701207657865" +
				"637574651204726561641a0d0a057465726d73120472" +
				"65616400000620f3ff20a448b0498fd354327ae3107a" +
				"d31cca87d8d36ea5710a5a90c0a2cde434"

				// Our request will list zero permissions since LND
				// won't recognize them.
			req := &lnrpc.CheckMacPermRequest{
				Macaroon:    macStr,
				Permissions: nil,
			}

			_, err := testNode.CheckMacaroonPermissions(ctxt, req)
			require.NoError(t, err)
		},
	}, {
		// Ninth test: check that CheckMacaroonPermissions detects a
		// macaroon that's timed out, even if it's unfamiliar with the
		// permissions.
		name: "detect timeout",
		run: func(ctxt context.Context, t *testing.T) {

			// A test macaroon that is timed out. The macaroon has
			// combined permissions from LND and daemons from
			// outside LND -- pool, loop, and faraday.
			macStr := "0201036c6e6402f003030a100240b01e10a85f41da11b2ad618684221201301a160a076163636f756e74120472656164120577726974651a160a0761646472657373120472656164120577726974651a0f0a0761756374696f6e1204726561641a0d0a0561756469741204726561641a0c0a04617574681204726561641a130a04696e666f120472656164120577726974651a100a08696e7369676874731204726561641a170a08696e766f69636573120472656164120577726974651a0f0a046c6f6f701202696e12036f75741a210a086d616361726f6f6e120867656e6572617465120472656164120577726974651a160a076d657373616765120472656164120577726974651a170a086f6666636861696e120472656164120577726974651a160a076f6e636861696e120472656164120577726974651a140a056f72646572120472656164120577726974651a140a057065657273120472656164120577726974651a0d0a0572617465731204726561641a160a0e7265636f6d6d656e646174696f6e1204726561641a0e0a067265706f72741204726561641a180a067369676e6572120867656e65726174651204726561641a1a0a0b73756767657374696f6e73120472656164120577726974651a150a04737761701207657865637574651204726561641a0d0a057465726d7312047265616400022a74696d652d6265666f726520323032312d30352d30395430323a32323a30382e3835393134383735315a00000620d20291e8f82100c1f5f2518cde12e61bdd4f4781aba561310363939f690450c4"

			// Our request will list zero permissions since LND
			// won't recognize them.
			req := &lnrpc.CheckMacPermRequest{
				Macaroon:    macStr,
				Permissions: nil,
			}

			resp, _ := testNode.CheckMacaroonPermissions(ctxt, req)
			assert.Equal(t, resp.Valid, false, "they should be equal")
		},
	}}

	for _, tc := range testCases {
		tc := tc
		ht.t.Run(tc.name, func(tt *testing.T) {
			ctxt, cancel := context.WithTimeout(
				context.Background(), defaultTimeout,
			)
			defer cancel()

			tc.run(ctxt, tt)
		})
	}
}

// testBakeMacaroon checks that when creating macaroons, the permissions param
// in the request must be set correctly, and the baked macaroon has the intended
// permissions.
func testBakeMacaroon(net *lntest.NetworkHarness, t *harnessTest) {
	var testNode = net.Alice

	testCases := []struct {
		name string
		run  func(ctxt context.Context, t *testing.T,
			adminClient lnrpc.LightningClient)
	}{{
		// First test: when the permission list is empty in the request,
		// an error should be returned.
		name: "no permission list",
		run: func(ctxt context.Context, t *testing.T,
			adminClient lnrpc.LightningClient) {

			req := &lnrpc.BakeMacaroonRequest{}
			_, err := adminClient.BakeMacaroon(ctxt, req)
			require.Error(t, err)
			assert.Contains(
				t, err.Error(), "permission list cannot be "+
					"empty",
			)
		},
	}, {
		// Second test: when the action in the permission list is not
		// valid, an error should be returned.
		name: "invalid permission list",
		run: func(ctxt context.Context, t *testing.T,
			adminClient lnrpc.LightningClient) {

			req := &lnrpc.BakeMacaroonRequest{
				Permissions: []*lnrpc.MacaroonPermission{{
					Entity: "macaroon",
					Action: "invalid123",
				}},
			}
			_, err := adminClient.BakeMacaroon(ctxt, req)
			require.Error(t, err)
			assert.Contains(
				t, err.Error(), "invalid permission action",
			)
		},
	}, {
		// Third test: when the entity in the permission list is not
		// valid, an error should be returned.
		name: "invalid permission entity",
		run: func(ctxt context.Context, t *testing.T,
			adminClient lnrpc.LightningClient) {

			req := &lnrpc.BakeMacaroonRequest{
				Permissions: []*lnrpc.MacaroonPermission{{
					Entity: "invalid123",
					Action: "read",
				}},
			}
			_, err := adminClient.BakeMacaroon(ctxt, req)
			require.Error(t, err)
			assert.Contains(
				t, err.Error(), "invalid permission entity",
			)
		},
	}, {
		// Fourth test: check that when no root key ID is specified, the
		// default root keyID is used.
		name: "default root key ID",
		run: func(ctxt context.Context, t *testing.T,
			adminClient lnrpc.LightningClient) {

			req := &lnrpc.BakeMacaroonRequest{
				Permissions: []*lnrpc.MacaroonPermission{{
					Entity: "macaroon",
					Action: "read",
				}},
			}
			_, err := adminClient.BakeMacaroon(ctxt, req)
			require.NoError(t, err)

			listReq := &lnrpc.ListMacaroonIDsRequest{}
			resp, err := adminClient.ListMacaroonIDs(ctxt, listReq)
			require.NoError(t, err)
			require.Equal(t, resp.RootKeyIds[0], uint64(0))
		},
	}, {
		// Fifth test: create a macaroon use a non-default root key ID.
		name: "custom root key ID",
		run: func(ctxt context.Context, t *testing.T,
			adminClient lnrpc.LightningClient) {

			rootKeyID := uint64(4200)
			req := &lnrpc.BakeMacaroonRequest{
				RootKeyId: rootKeyID,
				Permissions: []*lnrpc.MacaroonPermission{{
					Entity: "macaroon",
					Action: "read",
				}},
			}
			_, err := adminClient.BakeMacaroon(ctxt, req)
			require.NoError(t, err)

			listReq := &lnrpc.ListMacaroonIDsRequest{}
			resp, err := adminClient.ListMacaroonIDs(ctxt, listReq)
			require.NoError(t, err)

			// the ListMacaroonIDs should give a list of two IDs,
			// the default ID 0, and the newly created ID. The
			// returned response is sorted to guarantee the order so
			// that we can compare them one by one.
			sort.Slice(resp.RootKeyIds, func(i, j int) bool {
				return resp.RootKeyIds[i] < resp.RootKeyIds[j]
			})
			require.Equal(t, resp.RootKeyIds[0], uint64(0))
			require.Equal(t, resp.RootKeyIds[1], rootKeyID)
		},
	}, {
		// Sixth test: check the baked macaroon has the intended
		// permissions. It should succeed in reading, and fail to write
		// a macaroon.
		name: "custom macaroon permissions",
		run: func(ctxt context.Context, t *testing.T,
			adminClient lnrpc.LightningClient) {

			rootKeyID := uint64(4200)
			req := &lnrpc.BakeMacaroonRequest{
				RootKeyId: rootKeyID,
				Permissions: []*lnrpc.MacaroonPermission{{
					Entity: "macaroon",
					Action: "read",
				}},
			}
			bakeResp, err := adminClient.BakeMacaroon(ctxt, req)
			require.NoError(t, err)

			newMac, err := readMacaroonFromHex(bakeResp.Macaroon)
			require.NoError(t, err)
			cleanup, readOnlyClient := macaroonClient(
				t, testNode, newMac,
			)
			defer cleanup()

			// BakeMacaroon requires a write permission, so this
			// call should return an error.
			_, err = readOnlyClient.BakeMacaroon(ctxt, req)
			require.Error(t, err)
			require.Contains(t, err.Error(), "permission denied")

			// ListMacaroon requires a read permission, so this call
			// should succeed.
			listReq := &lnrpc.ListMacaroonIDsRequest{}
			_, err = readOnlyClient.ListMacaroonIDs(ctxt, listReq)
			require.NoError(t, err)

			// Current macaroon can only work on entity macaroon, so
			// a GetInfo request will fail.
			infoReq := &lnrpc.GetInfoRequest{}
			_, err = readOnlyClient.GetInfo(ctxt, infoReq)
			require.Error(t, err)
			require.Contains(t, err.Error(), "permission denied")
		},
	}, {
		// Seventh test: check that if the allow_external_permissions
		// flag is set, we are able to feed BakeMacaroons permissions
		// that LND is not familiar with.
		name: "allow external macaroon permissions",
		run: func(ctxt context.Context, t *testing.T,
			adminClient lnrpc.LightningClient) {

			// We'll try a permission from Pool to test that the
			// allow_external_permissions flag properly allows it.
			rootKeyID := uint64(4200)
			req := &lnrpc.BakeMacaroonRequest{
				RootKeyId: rootKeyID,
				Permissions: []*lnrpc.MacaroonPermission{{
					Entity: "account",
					Action: "read",
				}},
				AllowExternalPermissions: true,
			}

			_, err := adminClient.BakeMacaroon(ctxt, req)
			require.NoError(t, err)
		},
	}}

	for _, tc := range testCases {
		tc := tc
		t.t.Run(tc.name, func(tt *testing.T) {
			ctxt, cancel := context.WithTimeout(
				context.Background(), defaultTimeout,
			)
			defer cancel()

			adminMac, err := testNode.ReadMacaroon(
				testNode.AdminMacPath(), defaultTimeout,
			)
			require.NoError(tt, err)
			cleanup, client := macaroonClient(tt, testNode, adminMac)
			defer cleanup()

			tc.run(ctxt, tt, client)
		})
	}
}

// testDeleteMacaroonID checks that when deleting a macaroon ID, it removes the
// specified ID and invalidates all macaroons derived from the key with that ID.
// Also, it checks deleting the reserved marcaroon ID, DefaultRootKeyID or is
// forbidden.
func testDeleteMacaroonID(net *lntest.NetworkHarness, t *harnessTest) {
	var (
		ctxb     = context.Background()
		testNode = net.Alice
	)
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()

	// Use admin macaroon to create a connection.
	adminMac, err := testNode.ReadMacaroon(
		testNode.AdminMacPath(), defaultTimeout,
	)
	require.NoError(t.t, err)
	cleanup, client := macaroonClient(t.t, testNode, adminMac)
	defer cleanup()

	// Record the number of macaroon IDs before creation.
	listReq := &lnrpc.ListMacaroonIDsRequest{}
	listResp, err := client.ListMacaroonIDs(ctxt, listReq)
	require.NoError(t.t, err)
	numMacIDs := len(listResp.RootKeyIds)

	// Create macaroons for testing.
	rootKeyIDs := []uint64{1, 2, 3}
	macList := make([]string, 0, len(rootKeyIDs))
	for _, id := range rootKeyIDs {
		req := &lnrpc.BakeMacaroonRequest{
			RootKeyId: id,
			Permissions: []*lnrpc.MacaroonPermission{{
				Entity: "macaroon",
				Action: "read",
			}},
		}
		resp, err := client.BakeMacaroon(ctxt, req)
		require.NoError(t.t, err)
		macList = append(macList, resp.Macaroon)
	}

	// Check that the creation is successful.
	listReq = &lnrpc.ListMacaroonIDsRequest{}
	listResp, err = client.ListMacaroonIDs(ctxt, listReq)
	require.NoError(t.t, err)

	// The number of macaroon IDs should be increased by len(rootKeyIDs).
	require.Equal(t.t, numMacIDs+len(rootKeyIDs), len(listResp.RootKeyIds))

	// First test: check deleting the DefaultRootKeyID returns an error.
	defaultID, _ := strconv.ParseUint(
		string(macaroons.DefaultRootKeyID), 10, 64,
	)
	req := &lnrpc.DeleteMacaroonIDRequest{
		RootKeyId: defaultID,
	}
	_, err = client.DeleteMacaroonID(ctxt, req)
	require.Error(t.t, err)
	require.Contains(
		t.t, err.Error(), macaroons.ErrDeletionForbidden.Error(),
	)

	// Second test: check deleting the customized ID returns success.
	req = &lnrpc.DeleteMacaroonIDRequest{
		RootKeyId: rootKeyIDs[0],
	}
	resp, err := client.DeleteMacaroonID(ctxt, req)
	require.NoError(t.t, err)
	require.True(t.t, resp.Deleted)

	// Check that the deletion is successful.
	listReq = &lnrpc.ListMacaroonIDsRequest{}
	listResp, err = client.ListMacaroonIDs(ctxt, listReq)
	require.NoError(t.t, err)

	// The number of macaroon IDs should be decreased by 1.
	require.Equal(t.t, numMacIDs+len(rootKeyIDs)-1, len(listResp.RootKeyIds))

	// Check that the deleted macaroon can no longer access macaroon:read.
	deletedMac, err := readMacaroonFromHex(macList[0])
	require.NoError(t.t, err)
	cleanup, client = macaroonClient(t.t, testNode, deletedMac)
	defer cleanup()

	// Because the macaroon is deleted, it will be treated as an invalid one.
	listReq = &lnrpc.ListMacaroonIDsRequest{}
	_, err = client.ListMacaroonIDs(ctxt, listReq)
	require.Error(t.t, err)
	require.Contains(t.t, err.Error(), "cannot get macaroon")
}

// testStatelessInit checks that the stateless initialization of the daemon
// does not write any macaroon files to the daemon's file system and returns
// the admin macaroon in the response. It then checks that the password
// change of the wallet can also happen stateless.
func testStatelessInit(net *lntest.NetworkHarness, t *harnessTest) {
	var (
		initPw     = []byte("stateless")
		newPw      = []byte("stateless-new")
		newAddrReq = &lnrpc.NewAddressRequest{
			Type: AddrTypeWitnessPubkeyHash,
		}
	)

	// First, create a new node and request it to initialize stateless.
	// This should return us the binary serialized admin macaroon that we
	// can then use for further calls.
	carol, _, macBytes, err := net.NewNodeWithSeed(
		"Carol", nil, initPw, true,
	)
	require.NoError(t.t, err)
	if len(macBytes) == 0 {
		t.Fatalf("invalid macaroon returned in stateless init")
	}

	// Now make sure no macaroon files have been created by the node Carol.
	_, err = os.Stat(carol.AdminMacPath())
	require.Error(t.t, err)
	_, err = os.Stat(carol.ReadMacPath())
	require.Error(t.t, err)
	_, err = os.Stat(carol.InvoiceMacPath())
	require.Error(t.t, err)

	// Then check that we can unmarshal the binary serialized macaroon.
	adminMac := &macaroon.Macaroon{}
	err = adminMac.UnmarshalBinary(macBytes)
	require.NoError(t.t, err)

	// Find out if we can actually use the macaroon that has been returned
	// to us for a RPC call.
	conn, err := carol.ConnectRPCWithMacaroon(adminMac)
	require.NoError(t.t, err)
	defer conn.Close()
	adminMacClient := lnrpc.NewLightningClient(conn)
	ctxt, _ := context.WithTimeout(context.Background(), defaultTimeout)
	res, err := adminMacClient.NewAddress(ctxt, newAddrReq)
	require.NoError(t.t, err)
	if !strings.HasPrefix(res.Address, harnessNetParams.Bech32HRPSegwit) {
		t.Fatalf("returned address was not a regtest address")
	}

	// As a second part, shut down the node and then try to change the
	// password when we start it up again.
	if err := net.RestartNodeNoUnlock(carol, nil); err != nil {
		t.Fatalf("Node restart failed: %v", err)
	}
	changePwReq := &lnrpc.ChangePasswordRequest{
		CurrentPassword: initPw,
		NewPassword:     newPw,
		StatelessInit:   true,
	}
	ctxb := context.Background()
	response, err := carol.InitChangePassword(ctxb, changePwReq)
	require.NoError(t.t, err)

	// Again, make  sure no macaroon files have been created by the node
	// Carol.
	_, err = os.Stat(carol.AdminMacPath())
	require.Error(t.t, err)
	_, err = os.Stat(carol.ReadMacPath())
	require.Error(t.t, err)
	_, err = os.Stat(carol.InvoiceMacPath())
	require.Error(t.t, err)

	// Then check that we can unmarshal the new binary serialized macaroon
	// and that it really is a new macaroon.
	if err = adminMac.UnmarshalBinary(response.AdminMacaroon); err != nil {
		t.Fatalf("unable to unmarshal macaroon: %v", err)
	}
	if bytes.Equal(response.AdminMacaroon, macBytes) {
		t.Fatalf("expected new macaroon to be different")
	}

	// Finally, find out if we can actually use the new macaroon that has
	// been returned to us for a RPC call.
	conn2, err := carol.ConnectRPCWithMacaroon(adminMac)
	require.NoError(t.t, err)
	defer conn2.Close()
	adminMacClient = lnrpc.NewLightningClient(conn2)

	// Changing the password takes a while, so we use the default timeout
	// of 30 seconds to wait for the connection to be ready.
	ctxt, _ = context.WithTimeout(context.Background(), defaultTimeout)
	res, err = adminMacClient.NewAddress(ctxt, newAddrReq)
	require.NoError(t.t, err)
	if !strings.HasPrefix(res.Address, harnessNetParams.Bech32HRPSegwit) {
		t.Fatalf("returned address was not a regtest address")
	}
}

// readMacaroonFromHex loads a macaroon from a hex string.
func readMacaroonFromHex(macHex string) (*macaroon.Macaroon, error) {
	macBytes, err := hex.DecodeString(macHex)
	if err != nil {
		return nil, err
	}

	mac := &macaroon.Macaroon{}
	if err := mac.UnmarshalBinary(macBytes); err != nil {
		return nil, err
	}
	return mac, nil
}

func macaroonClient(t *testing.T, testNode *lntest.HarnessNode,
	mac *macaroon.Macaroon) (func(), lnrpc.LightningClient) {

	conn, err := testNode.ConnectRPCWithMacaroon(mac)
	require.NoError(t, err, "connect to alice")

	cleanup := func() {
		err := conn.Close()
		require.NoError(t, err, "close")
	}
	return cleanup, lnrpc.NewLightningClient(conn)
}
