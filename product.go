package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	pesan_backend "github.com/miltsm/pesan-backend/pesan/go"
)

func (s *pesanServer) CreateNewProduct(ctx context.Context, r *pesan_backend.NewProductRequest) (*pesan_backend.NewProductReply, error) {
	newId := uuid.New()
	_, err := newProductStmt.Exec(newId, r.Name, r.Description, r.UnitLabel, r.UnitPrice)
	if err != nil {
		return nil, err
	}
	var categoryErrs []string
	for i := 0; i < len(r.Categories); i++ {
		category := r.Categories[i]
		_, err = newCategoryStmt.Exec(
			category.CategoryId,
			category.Name,
			category.Description,
			category.AvailableFrom.AsTime(),
			category.AvailableUntil.AsTime(),
			category.AvailableWeekly)
		if err != nil {
			if strings.ContainsAny(err.Error(), "duplicate key value violates unique") {
				_, err = updateCategoryStmt.Exec(
					category.CategoryId,
					category.Name,
					category.Description,
					category.AvailableFrom.AsTime(),
					category.AvailableUntil.AsTime(),
					category.AvailableWeekly)
				if err != nil {
					categoryErrs = append(categoryErrs, *category.CategoryId)
					fmt.Printf("[ERROR] unable to update category: %s\n", err.Error())
				} else {
					_, err = newProductCategories.Exec(newId, category.CategoryId)
					if err != nil {
						fmt.Printf("[ERROR] unable to added product-category:\n%s(%s) & %s(%s)",
							r.Name, newId, *category.Name, *category.CategoryId)
					} else {
						fmt.Printf("[INFO] product-categories added!\n")
					}
				}
			} else {
				categoryErrs = append(categoryErrs, *category.CategoryId)
				fmt.Printf("[WARN] unable to insert category: %s\n", err.Error())
			}
		} else {
			// product-categories relation
			_, err = newProductCategories.Exec(newId, category.CategoryId)
			if err != nil {
				fmt.Printf("[ERROR] unable to added product-category:\n%s(%s) & %s(%s)",
					r.Name, newId, *category.Name, *category.CategoryId)
			} else {
				fmt.Printf("[INFO] product-categories added!\n")
			}
		}
	}
	return &pesan_backend.NewProductReply{
		NewProductId: newId.String(),
	}, nil
}
