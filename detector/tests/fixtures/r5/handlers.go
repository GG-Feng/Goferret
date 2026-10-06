package main

import (
	"context"
	"errors"
)

type Item struct{ Owner string }
type User struct{ Name string }
type Store interface {
	GetItem(ctx context.Context, id string) (Item, error)
	DeleteItem(ctx context.Context, id string) error
	GetItemURL(ctx context.Context, id string) (string, error)
}
type GetItemRequest struct{ Id string }

func MustHaveUser(ctx context.Context) User { return User{} }

type Handler struct{ store Store }

func (h *Handler) GetItem(ctx context.Context, request GetItemRequest) (Item, error) {
	it, err := h.store.GetItem(ctx, request.Id)
	if err != nil {
		return Item{}, err
	}
	if MustHaveUser(ctx).Name != it.Owner {
		return Item{}, errors.New("forbidden")
	}
	return it, nil
}

func (h *Handler) DeleteItem(ctx context.Context, request GetItemRequest) error {
	it, err := h.store.GetItem(ctx, request.Id)
	if err != nil || MustHaveUser(ctx).Name != it.Owner {
		return errors.New("forbidden")
	}
	return h.store.DeleteItem(ctx, request.Id)
}

// missing the ownership check its siblings perform
func (h *Handler) GetDownloadURL(ctx context.Context, request GetItemRequest) (string, error) {
	return h.store.GetItemURL(ctx, request.Id)
}

// all handlers of this type rely on middleware: not reported
type Public struct{ store Store }

func (p *Public) A(ctx context.Context, request GetItemRequest) (Item, error) {
	return p.store.GetItem(ctx, request.Id)
}
func (p *Public) B(ctx context.Context, request GetItemRequest) (string, error) {
	return p.store.GetItemURL(ctx, request.Id)
}
func (p *Public) C(ctx context.Context, request GetItemRequest) error {
	return p.store.DeleteItem(ctx, request.Id)
}
