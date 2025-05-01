package main

import (
	"context"
	"database/sql"
	"encoding/json"

	"strings"

	"fmt"
	"time"

	"github.com/google/uuid"

	stub "github.com/miltsm/pesan-grpc-stubs/go"

	"google.golang.org/grpc/codes"

	"google.golang.org/grpc/status"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// NOTE: new shop
func (s *protectedSrvr) CreateNewShop(ctx context.Context, r *stub.NewShopRequest) (*stub.NewShopReply, error) {
	newSesh, opts, err := requiresRefreshOrReauth(ctx, r.RefreshToken, r.RAuth)
	if opts != nil {
		return &stub.NewShopReply{
			Options: opts,
		}, nil
	}

	userId := ctx.Value("user_id").(*uuid.UUID)

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

	newId := uuid.New()
	_, err = statements[CreateAShop].Exec(newId, r.Name, r.Tags, openTimeStr, closingTimeStr, r.Contacts, operationsStr, r.Location, userId)
	if err != nil {
		if err.Error() == "Cannot insert more than 1 row at once" {
			return nil, status.Error(codes.ResourceExhausted, "[ERROR] shop==1")
		} else {
			return nil, status.Errorf(codes.Internal, "[ERROR] %v", err)
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
