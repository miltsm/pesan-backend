package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"sync"

	"strings"

	"fmt"
	"time"

	//"firebase.google.com/go/messaging"
	"firebase.google.com/go/messaging"
	"github.com/google/uuid"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	stub "github.com/miltsm/pesan-grpc-stubs/go"

	"google.golang.org/grpc/codes"

	"google.golang.org/grpc/status"

	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type ShopMonitor struct {
	shopId       string
	shopName     string
	streamName   string
	consumerName string
	jsc          jetstream.Consumer
	stopChan     chan struct{}
	disconnected bool
}

type Device struct {
	DeviceId uuid.UUID
	FCMToken string
}

// NOTE: new shop
func (s *protectedSrvr) CreateNewShop(ctx context.Context, r *stub.NewShopRequest) (*stub.NewShopReply, error) {
	newSesh, opts, err := requiresRefreshOrReauth(ctx, r.RefreshToken, r.RAuth)
	if opts != nil {
		return &stub.NewShopReply{
			Options: opts,
		}, nil
	}

	userId := ctx.Value("user_id").(uuid.UUID)

	if len(r.Name) < 6 {
		return nil, status.Errorf(codes.InvalidArgument, "[WARN] name<6")
	}

	openTimeStr := fmt.Sprintf("%d:%d:00", r.OpensAt.Hour, r.OpensAt.Minute)
	closingTimeStr := fmt.Sprintf("%d:%d:00", r.ClosesAt.Hour, r.ClosesAt.Minute)

	openTime, err := time.Parse(time.TimeOnly, openTimeStr)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "[DEBUG] %v", err)
	}

	var closingTime time.Time
	closingTime, err = time.Parse(time.TimeOnly, closingTimeStr)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "[DEBUG] %v", err)
	}

	if openTime.Compare(closingTime) == 1 {
		return nil, status.Error(codes.InvalidArgument, "[WARN] opentime>closingtime")
	}

	if len(r.OperationDays) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[WARN] operationdays==0")
	}

	var operationsStr []string
	for i := 0; i < len(r.OperationDays); i++ {
		operationsStr = append(operationsStr, r.OperationDays[i].String())
	}

	// TODO: transaction commit/rollback when subscribe error
	var deviceRows *sql.Rows
	deviceRows, err = statements[CreateAShopAndReturnDevices].Query(r.Name, r.Tags, openTimeStr, closingTimeStr, r.Contacts, operationsStr, r.Location, userId)
	if err != nil {
		if err.Error() == "Cannot insert more than 1 row at once" {
			return nil, status.Error(codes.ResourceExhausted, "[ERROR] shop==1")
		} else {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}
	}

	var newId uuid.UUID
	devices := []uuid.UUID{}
	tokens := []string{}
	for deviceRows.Next() {
		var deviceId uuid.UUID
		var token *string
		err2 := deviceRows.Scan(&newId, &deviceId, &token)
		if err2 != nil {
			fmt.Printf("[ERROR] token error when subscribing: %v\n", err2)
			continue
		}
		devices = append(devices, deviceId)
		fmt.Println(tokens)
		if token != nil && len(*token) > 0 {
			tokens = append(tokens, *token)
		}
	}

	shopTopic := fmt.Sprintf("shop_%s_intrnl", newId)
	var tpcMgmtRes *messaging.TopicManagementResponse
	tpcMgmtRes, err = fbMsgClient.SubscribeToTopic(ctx, tokens, shopTopic)
	if err != nil {
		// NOTE: maybe not return error; txn update later
		log.Printf("[ERROR] %v", err)
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	// NOTE: remove those device that fails from devices slice
	for i := 0; i < len(tpcMgmtRes.Errors); i++ {
		failedToSubIdx := tpcMgmtRes.Errors[i].Index
		devices = append(devices[:failedToSubIdx], devices[failedToSubIdx+1:]...)
	}

	// NOTE: create shop devices after successful subscription
	for i := 0; i < len(devices); i++ {
		_, err2 := statements[CreateAShopDevice].Exec(shopTopic, newId, devices[i])
		if err2 != nil {
			log.Printf("[ERROR] unable to create shop device\nreason: %v\n", err2)
			continue
		}
	}

	return &stub.NewShopReply{
		ShopId: &stub.UuId{
			Id: []byte(newId.String()),
		},
		LastUpdatedAt: timestamppb.New(time.Now()),
		FreshSession:  newSesh,
	}, nil
}

// NOTE: shop page
func (s *protectedSrvr) GetShops(ctx context.Context, r *stub.ShopRequest) (*stub.ShopPage, error) {

	newSesh, opts, err := requiresRefreshOrReauth(ctx, r.RefreshToken, r.RAuth)
	if opts != nil {
		return &stub.ShopPage{
			Options: opts,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	userId := ctx.Value("user_id").(uuid.UUID)

	var rows *sql.Rows
	rows, err = statements[ReadShops].Query(userId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}
	defer rows.Close()

	var shops []*stub.ShopRole
	// NOTE: updated_at is used for syncing purpose between client & server
	for rows.Next() {
		var shopId, roleId uuid.UUID
		var name, location string
		var opensAtStr, closesAtStr sql.NullString
		var tagsStr, opDaysStr string
		var contactsB []byte
		var editShop, openCloseShop, createProducts, editProducts, deleteProducts, createOrders, editOrders sql.NullBool

		err = rows.Scan(&shopId, &name, &tagsStr, &opensAtStr, &closesAtStr, &contactsB, &opDaysStr, &location, &roleId, &editShop, &openCloseShop, &createProducts, &editProducts, &deleteProducts, &createOrders, &editOrders)
		if err != nil {
			logError(93, err)
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}

		tagsStr = strings.TrimPrefix(tagsStr, "{")
		tagsStr = strings.TrimSuffix(tagsStr, "}")

		tags := strings.Split(tagsStr, ",")

		var opensAt, closesAt time.Time
		opensAt, err = time.Parse(time.TimeOnly, opensAtStr.String)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}

		closesAt, err = time.Parse(time.TimeOnly, closesAtStr.String)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}

		var contacts []*stub.Contact
		err = json.Unmarshal(contactsB, &contacts)
		if err != nil {
			logError(128, err)
			return nil, status.Errorf(codes.Internal, "[ERROR %v]", err)
		}

		opDaysStr = strings.TrimPrefix(opDaysStr, "{")
		opDaysStr = strings.TrimSuffix(opDaysStr, "}")
		days := strings.Split(opDaysStr, ",")

		var opDays []stub.Day
		for _, day := range days {
			opDays = append(opDays, stub.Day(stub.Day_value[day]))
		}

		shops = append(shops, &stub.ShopRole{
			Shop: &stub.ShopPb{
				ShopId: &stub.UuId{
					Id: []byte(shopId.String()),
				},
				Name: name,
				Tags: tags,
				OpensAt: &stub.OperationHour{
					Hour:   int32(opensAt.Hour()),
					Minute: int32(opensAt.Minute()),
				},
				ClosesAt: &stub.OperationHour{
					Hour:   int32(closesAt.Hour()),
					Minute: int32(closesAt.Minute()),
				},
				Contacts:      contacts,
				OperationDays: opDays,
				Location:      &location,
			},
			Role: &stub.RolePb{
				RoleId: &stub.UuId{
					Id: []byte(roleId.String()),
				},
				EditShop:       editShop.Bool,
				OpenCloseShop:  openCloseShop.Bool,
				CreateProducts: createProducts.Bool,
				EditProducts:   editProducts.Bool,
				DeleteProducts: deleteProducts.Bool,
				CreateOrders:   createOrders.Bool,
				EditOrders:     editOrders.Bool,
			},
		})
	}
	return &stub.ShopPage{
		Shops:        shops,
		FreshSession: newSesh,
	}, nil
}

func (prtc *protectedSrvr) ShopDeviceStatus(ctx context.Context, r *stub.ShopDeviceStatusRequest) (*stub.ShopDeviceStatusReply, error) {

	shopId, err := uuid.ParseBytes(r.ShopId.Id)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] invalid shop ID")
	}

	var deviceId uuid.UUID
	deviceId, err = uuid.ParseBytes(r.DeviceId.Id)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] invalid device id")
	}

	strmNm := fmt.Sprintf("ORDERS_%s", shopId)
	var strm jetstream.Stream
	strm, err = shopJetstream.Stream(ctx, strmNm)
	if err != nil {
		if errors.Is(err, jetstream.ErrStreamNotFound) {
			return nil, status.Errorf(codes.NotFound, "[ERROR] shop is closed")
		} else {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}
	}

	_, err = strm.Consumer(ctx, deviceId.String())
	if err != nil {
		if errors.Is(err, jetstream.ErrConsumerNotFound) {
			return &stub.ShopDeviceStatusReply{
				Status: stub.DeviceStatus_offline,
			}, nil
		} else {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}
	}

	// NOTE: next check whether this shop device is active
	var deviceStatus *stub.DeviceStatus
	var lastActive *time.Time
	err = statements[ReadAShopDevice].QueryRow(shopId, deviceId).Scan(&deviceStatus, &lastActive)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "[ERROR] device doesnt exist")
		} else {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}
	}

	// NOTE: if connected but last_active has past 3 minutes, then we re-ping again
	if *deviceStatus == stub.DeviceStatus_online && time.Since(*lastActive) > 2*time.Minute {
		// NOTE: re-ping
		subject := fmt.Sprintf("shop.device.%s", deviceId.String())
		var msg *nats.Msg
		msg, err = shopJetstream.Conn().Request(subject, []byte("ping"), 10*time.Second)
		if err != nil {
			*deviceStatus = stub.DeviceStatus_offline
		}

		if string(msg.Data) == "ping" {
			// NOTE: do nothing; the device is indeed actively listening
		}
	}

	return &stub.ShopDeviceStatusReply{
		Status: *deviceStatus,
	}, nil
}

func (prtc *protectedSrvr) OpenShop(ctx context.Context, r *stub.OpenShopRequest) (*emptypb.Empty, error) {
	shopId, err := uuid.ParseBytes(r.ShopId.Id)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] invalid shop ID")
	}

	deviceId, err := uuid.ParseBytes(r.DeviceId.Id)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] invalid device ID")
	}

	// NOTE: check if their publicKey exist or not
	userId := ctx.Value("user_id").(uuid.UUID)
	var currentNkey sql.NullString
	err = statements[ReadDeviceNKey].QueryRow(userId).Scan(&currentNkey)
	if err != nil {
		// NOTE: ask client to register new NATS public key
		if errors.Is(err, sql.ErrNoRows) {
			if len(r.O4BPk) == 0 {
				return nil, status.Error(codes.NotFound, "[ERROR] public key yet to register")
			}
		} else {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}
	}

	if len(currentNkey.String) == 0 && (r.O4BPk == nil || (r.O4BPk != nil && len(r.O4BPk) == 0)) {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] public key registration required!")
	}

	// NOTE: update public key if provided
	if r.O4BPk != nil && len(string(r.O4BPk)) > 0 && strings.Compare(currentNkey.String, string(r.O4BPk)) != 0 {
		_, err2 := statements[UpdateDeviceNKey].Exec(string(r.O4BPk), deviceId)
		if err2 != nil {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}
	}

	// TODO: whitelist public key

	strmNm := fmt.Sprintf("ORDERS_%s", shopId)
	orderSubject := fmt.Sprintf("orders.%s", shopId)

	// NOTE: closing time check, can be past
	// front end will provide time selector UI
	closeShopDuration := time.Until(r.OpenUntil.AsTime())
	if closeShopDuration < 0 {
		return nil, status.Errorf(codes.OutOfRange, "[ERROR] Closing time has past")
	}
	fmt.Printf("stream name: %v\nends at: %v\n", strmNm, closeShopDuration)

	var txn *sql.Tx
	txn, err = db.Begin()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	_, err = txn.Stmt(statements[UpdateAShopDevice]).Exec(time.Now(), stub.DeviceStatus_online, shopId, deviceId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	_, err = shopJetstream.CreateStream(ctx, jetstream.StreamConfig{
		Name:     strmNm,
		Subjects: []string{orderSubject},
		MaxAge:   closeShopDuration,
		// NOTE: ample time for seller to reconnect back
		ConsumerLimits: jetstream.StreamConsumerLimits{
			InactiveThreshold: 10 * time.Minute,
		},
		Description: shopId.String(),
	})
	if err != nil {
		// NOTE: rollback to closed status
		err2 := txn.Rollback()
		log.Printf("[ERROR] %v", err2)
		// NOTE: stream already exist check
		if errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
			return nil, status.Error(codes.AlreadyExists, "[ERROR] Shop already opened")
		} else {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
		}
	}

	err = txn.Commit()
	if err != nil {
		// NOTE: need status to be open
		shopJetstream.DeleteStream(ctx, strmNm)
		return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
	}

	return &emptypb.Empty{}, nil
}

func (prtc *protectedSrvr) CloseShop(ctx context.Context, r *stub.CloseShopRequest) (*emptypb.Empty, error) {
	shopId, err := uuid.ParseBytes(r.ShopId.Id)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "[ERROR] invalid shop ID")
	}

	strmName := fmt.Sprintf("ORDERS_%s", shopId)
	err = shopJetstream.DeleteStream(ctx, strmName)
	if err != nil {
		switch {
		case errors.Is(err, jetstream.ErrStreamNotFound):
			return nil, status.Errorf(codes.NotFound, "[ERROR] Not found. Shop may be close already\n")
		default:
			return nil, status.Errorf(codes.Internal, "[ERROR] %v\n", err)
		}
	}

	return &emptypb.Empty{}, nil
}

const (
	checkInterval = 5 * time.Minute
	maxWorkers    = 10
	cleanupTime   = "59 23 * * *"
)

var (
	isMonitoringActiveShop chan bool
	shopChan               = make(chan string, 100)
	// NOTE: track active device
	activeShopDevices = make(map[string]ShopDevice)
	// NOTE: for thread safety
	mutex sync.Mutex
)

// TODO: set this when the is open by the user
type ShopDevice struct {
	ShopId   uuid.UUID
	ShopName string
}

func initialiseShopWorkerPeriodicChecks() {
	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for strmNm := range shopChan {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				shopIdStr, ok := strings.CutPrefix(strmNm, "ORDERS_")
				if !ok {
					closeShopStream(ctx, strmNm)
				}

				shopId, err := uuid.Parse(shopIdStr)
				if err != nil {
					log.Printf("[ERROR] invalid shop id: %v\n", err)
					// NOTE: invalid shop id; close stream immediately
					closeShopStream(ctx, strmNm)
					continue
				}

				var strm jetstream.Stream
				strm, err = shopJetstream.Stream(ctx, strmNm)
				if err != nil {
					// NOTE: this shouldnt happen
					log.Printf("[DEBUG] %v", err)
					continue
				}

				// NOTE: we can close this bcos they have 10 minutes to reconnect from inactiveThrehold
				if strm.CachedInfo().State.Consumers == 0 {
					closeShopStream(ctx, strmNm)
					notifyShopCloses(shopId)
					// TODO: notify customer if there's NumPending > 0; this can be done via customer topic
					continue
				}

				pingSubject := fmt.Sprintf("%s.test", strmNm)
				var msg *nats.Msg
				// NOTE: this will ping all devices of the shop
				msg, err = shopJetstream.Conn().Request(pingSubject, []byte("ping"), 10*time.Second)
				if err != nil {
					notifyShopUnattended(shopId)
					// TODO: notify customer if there's NumPending > 0
					continue
				}

				// NOTE: atleast 1 device should return 'pong' to keep the shop open
				if string(msg.Data) == "pong" {
					continue
				}

				// NOTE: if not 'pong', suspicious!
				closeShopStream(ctx, strmNm)
			}
		}()
	}

	// NOTE: starts periodic checks
	ticker := time.NewTicker(checkInterval)
	//defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				// NOTE: this is shop-level, not per device level check; only one active device needed to keep the shop open(stream)
				ctx := context.Background()
				streams := shopJetstream.StreamNames(ctx)
				// TODO: shut timer off if there's none; reactive through OpenShop()
				for strmNm := range streams.Name() {
					log.Printf("[INFO] pinging stream: %s\n", strmNm)
					shopChan <- strmNm
				}
			case <-isMonitoringActiveShop:
				close(shopChan)
				log.Println("[INFO] Stopping periodic checks")
				return
			}
		}
	}()

	fmt.Println("[INFO] Running active shop interval checks..")
}

func notifyShopUnattended(shopId uuid.UUID) error {
	var shopNm string
	err := statements[ReadAShop].QueryRow(shopId).Scan(&shopNm)
	if err != nil {
		log.Printf("[ERROR] %v", err)
		return err
	}

	// NOTE: Send push notification to merchant
	ctx := context.Background()
	var client *messaging.Client
	client, err = fb.Messaging(ctx)
	if err != nil {
		log.Printf("[ERROR] %v", err)
		return err
	}
	topic := fmt.Sprintf("shop_%s_intrnl", shopId)
	_, err = client.Send(ctx, &messaging.Message{
		Topic: topic,
		Android: &messaging.AndroidConfig{
			Notification: &messaging.AndroidNotification{
				TitleLocKey: "title_shop_unattended",
				TitleLocArgs: []string{
					shopNm,
				},
				BodyLocKey:  "body_shop_unattended",
				BodyLocArgs: []string{shopNm},
				ChannelID:   "o4b_channel_1",
				ClickAction: "reconnect_live_order",
				Priority:    messaging.PriorityHigh,
			},
		},
		Data: map[string]string{
			"shop_id": shopId.String(),
			"event":   "live_order_disconnect",
		},
	})
	if err != nil {
		log.Printf("[ERROR] %v", err)
		return err
		//		if messaging.IsRegistrationTokenNotRegistered(err) {
		//			// NOTE: remove this token from db
		//		}
	}
	log.Printf("[INFO] shop %v has been notified\n", shopId)
	return nil
}

func notifyShopCloses(shopId uuid.UUID) error {
	var shopNm string
	err := statements[ReadAShop].QueryRow(shopId).Scan(&shopNm)
	if err != nil {
		log.Printf("[ERROR] %v", err)
		return err
	}

	ctx := context.Background()
	var client *messaging.Client
	client, err = fb.Messaging(ctx)
	if err != nil {
		log.Printf("[ERROR] %v", err)
		return err
	}

	topic := fmt.Sprintf("shop_%s_intrnl", shopId)
	_, err = client.Send(ctx, &messaging.Message{
		Topic: topic,
		Android: &messaging.AndroidConfig{
			Notification: &messaging.AndroidNotification{
				TitleLocKey:  "title_shop_closes",
				TitleLocArgs: []string{shopNm},
				BodyLocKey:   "body_shop_closes",
				BodyLocArgs:  []string{shopNm},
				ChannelID:    "o4b_channel_1",
				Priority:     messaging.PriorityDefault,
			},
		},
		Data: map[string]string{
			"shop_id": shopId.String(),
		},
	})
	if err != nil {
		log.Printf("[ERROR] %v", err)
		return err
	}
	log.Printf("[INFO] shop %v has been notified", shopId)
	return nil
}

// NOTE: check atleast one device is actively receiving orders
// TODO: can delete this if all fine
//func checkDeviceActivity(shopId, deviceId uuid.UUID) error {
//	strmNm := fmt.Sprintf("ORDERS_%s", shopId.String())
//
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//
//	strm, err := shopJetstream.Stream(ctx, strmNm)
//	if err != nil {
//		return fmt.Errorf("[ERROR] failed to get stream: %v\n", err)
//	}
//
//	// NOTE: closes immediately bcos durable buffer from 10 minutes; and the first 5 min was notified to the seller regarding the inactivity
//	if strm.CachedInfo().State.Consumers == 0 {
//		updateDeviceStatus(shopId, deviceId, stub.DeviceStatus_offline)
//		return nil
//	}
//
//	// NOTE: this subject is check atleast there's one reply from any of the device
//	subject := fmt.Sprintf("shop.%s.test", shopId.String())
//	var dvcStts *stub.DeviceStatus
//	dvcStts, err = pingDevice(subject)
//	if err != nil {
//		// NOTE: this helps to reduce active shops query every 5 minutes
//		updateDeviceStatus(shopId, deviceId, stub.DeviceStatus_offline)
//
//		// TODO: send notification to seller that theres no active device listening for new orders
//		notifySellerRegardingShopStatus()
//
//		// TODO: to notify customer that the seller is currently inactive. let them decide whether to wait or cancel their pending orders [Low Priority; Order module cycle, customer app]
//
//		return fmt.Errorf("[ERROR] failed to get stream: %v\n", err)
//	}
//
//	updateDeviceStatus(shopId, deviceId, *dvcStts)
//	return nil
//}
//
//// NOTE: reason to isolate this is prevent notification push when the user call ShopDeviceStatus check
//// TODO: can delete this if all ok
//func pingDevice(subject string) (*stub.DeviceStatus, error) {
//	msg, err := shopJetstream.Conn().Request(subject, []byte("ping"), 10*time.Second)
//	if err != nil {
//		log.Printf("[ERROR] %v", err)
//		return stub.DeviceStatus_offline.Enum(), nil
//	}
//	if string(msg.Data) == "pong" {
//		return stub.DeviceStatus_online.Enum(), nil
//	}
//	return nil, fmt.Errorf("[ERROR] unexpected response: %s", string(msg.Data))
//}
//
//// TODO: can delete if all ok
//func removeShopDeviceFromIntervalQueue(shopId, deviceId uuid.UUID) {
//	key := fmt.Sprintf("%s:%s", shopId.String(), deviceId.String())
//	mutex.Lock()
//	delete(activeShopDevices, key)
//	mutex.Unlock()
//}

func closeShopStream(ctx context.Context, streamName string) {
	err := shopJetstream.DeleteStream(ctx, streamName)
	if err != nil {
		log.Printf("[ERROR] unable to delete %s stream", streamName)
	}
}

// TODO: can delete if all ok
//func updateDeviceStatus(shopId, deviceId uuid.UUID, status stub.DeviceStatus) error {
//	var err error
//	if status == stub.DeviceStatus_online {
//		_, err = statements[UpdateAShopDevice].Exec(time.Now(), status, shopId, deviceId)
//	} else {
//		_, err = statements[UpdateAShopDeviceStatus].Exec(status, shopId, deviceId)
//
//		if status == stub.DeviceStatus_offline {
//			ctx := context.Background()
//			strmNm := fmt.Sprintf("ORDERS_%s", shopId.String())
//			closeShopStream(ctx, strmNm)
//			removeShopDeviceFromIntervalQueue(shopId, deviceId)
//
//			// TODO: send notification to seller
//			notifySellerRegardingShopStatus()
//
//			// TODO: send notification to customer; tell to wait for bit [Low Priority; Order module cycle, customer app]
//		}
//	}
//
//	if err != nil {
//		return fmt.Errorf("[ERROR] failed to update devices: %v\n", err)
//	}
//	return nil
//}
