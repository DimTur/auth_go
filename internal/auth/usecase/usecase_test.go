package usecase_test

import (
	"auth_go_hw/internal/auth/entity"
	"auth_go_hw/internal/auth/usecase"
	"auth_go_hw/internal/gateway/http/gen"
	"auth_go_hw/mocks"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestLoginUser(t *testing.T) {
	ctrl := gomock.NewController(t)

	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockCryptoPassword := mocks.NewMockCryptoPassword(ctrl)
	mockJWTManager := mocks.NewMockJWTManager(ctrl)

	type args struct {
		ctx context.Context
		req gen.PostLoginRequestObject
	}
	tests := []struct {
		name             string
		args             args
		setupMocks       func()
		expectedResponse interface{}
		expectedError    error
	}{
		{
			name: "successful login",
			args: args{
				ctx: context.Background(),
				req: gen.PostLoginRequestObject{
					Body: &gen.PostLoginJSONRequestBody{
						Username: "user1",
						Password: "validpassword",
					},
				},
			},
			setupMocks: func() {
				mockUserRepo.EXPECT().
					FindUserByLogin(gomock.Any(), "user1").
					Return(entity.UserAccount{Username: "user1", Password: "hashedpassword", UserID: "user1"}, nil)

				mockCryptoPassword.EXPECT().
					ComparePassword("hashedpassword", "validpassword").
					Return(true)

				mockUserRepo.EXPECT().
					FindRefreshToken(gomock.Any(), "user1").
					Return(entity.RefreshToken{Token: "existingToken"}, nil)

				mockUserRepo.EXPECT().
					DeleteRefreshToken(gomock.Any(), "existingToken").
					Return(nil)

				mockJWTManager.EXPECT().
					IssueAccessToken("user1").
					Return("validAccessToken", nil)

				mockJWTManager.EXPECT().
					IssueRefreshToken("user1").
					Return("validRefreshToken", nil)

				mockJWTManager.EXPECT().
					GetRefreshExpiresIn().
					Return(time.Hour * 24)

				mockUserRepo.EXPECT().
					SaveRefreshToken(gomock.Any(), "user1", "validRefreshToken", gomock.Any()).
					Return(nil)
			},
			expectedResponse: gen.PostLogin200JSONResponse{
				AccessToken:  "validAccessToken",
				RefreshToken: "validRefreshToken"},
			expectedError: nil,
		},
		{
			name: "user not found",
			args: args{
				ctx: context.Background(),
				req: gen.PostLoginRequestObject{
					Body: &gen.PostLoginJSONRequestBody{
						Username: "user1",
						Password: "validpassword",
					},
				},
			},
			setupMocks: func() {
				mockUserRepo.EXPECT().
					FindUserByLogin(gomock.Any(), "user1").
					Return(entity.UserAccount{}, assert.AnError)
			},
			expectedResponse: gen.PostLogin500JSONResponse{},
			expectedError:    nil,
		},
		{
			name: "invalid password",
			args: args{
				ctx: context.Background(),
				req: gen.PostLoginRequestObject{
					Body: &gen.PostLoginJSONRequestBody{
						Username: "user1",
						Password: "wrongpassword",
					},
				},
			},
			setupMocks: func() {
				mockUserRepo.EXPECT().
					FindUserByLogin(gomock.Any(), "user1").
					Return(entity.UserAccount{UserID: "user1", Password: "hashedpassword"}, nil)

				mockCryptoPassword.EXPECT().
					ComparePassword("hashedpassword", "wrongpassword").
					Return(false)
			},
			expectedResponse: gen.PostLogin401JSONResponse{Error: "unauth"},
			expectedError:    nil,
		},
		{
			name: "error issuing access token",
			args: args{
				ctx: context.Background(),
				req: gen.PostLoginRequestObject{
					Body: &gen.PostLoginJSONRequestBody{
						Username: "user1",
						Password: "validpassword",
					},
				},
			},
			setupMocks: func() {
				mockUserRepo.EXPECT().
					FindUserByLogin(gomock.Any(), "user1").
					Return(entity.UserAccount{UserID: "user1", Password: "hashedpassword"}, nil)

				mockCryptoPassword.EXPECT().
					ComparePassword("hashedpassword", "validpassword").
					Return(true)

				mockJWTManager.EXPECT().
					IssueAccessToken("user1").
					Return("", assert.AnError)

				mockUserRepo.EXPECT().
					FindRefreshToken(gomock.Any(), "user1").
					Return(entity.RefreshToken{}, nil)
			},
			expectedResponse: gen.PostLogin500JSONResponse{},
			expectedError:    assert.AnError,
		},
		{
			name: "error issuing refresh token",
			args: args{
				ctx: context.Background(),
				req: gen.PostLoginRequestObject{
					Body: &gen.PostLoginJSONRequestBody{
						Username: "user1",
						Password: "validpassword",
					},
				},
			},
			setupMocks: func() {
				mockUserRepo.EXPECT().
					FindUserByLogin(gomock.Any(), "user1").
					Return(entity.UserAccount{UserID: "user1", Password: "hashedpassword"}, nil)

				mockCryptoPassword.EXPECT().
					ComparePassword("hashedpassword", "validpassword").
					Return(true)

				mockJWTManager.EXPECT().
					IssueAccessToken("user1").
					Return("validAccessToken", nil)

				mockJWTManager.EXPECT().
					IssueRefreshToken("user1").
					Return("", assert.AnError)

				mockUserRepo.EXPECT().
					FindRefreshToken(gomock.Any(), "user1").
					Return(entity.RefreshToken{}, nil)
			},
			expectedResponse: gen.PostLogin500JSONResponse{},
			expectedError:    assert.AnError,
		},
		{
			name: "error saving refresh token",
			args: args{
				ctx: context.Background(),
				req: gen.PostLoginRequestObject{
					Body: &gen.PostLoginJSONRequestBody{
						Username: "user1",
						Password: "validpassword",
					},
				},
			},
			setupMocks: func() {
				mockUserRepo.EXPECT().
					FindUserByLogin(gomock.Any(), "user1").
					Return(entity.UserAccount{UserID: "user1", Password: "hashedpassword"}, nil)

				mockCryptoPassword.EXPECT().
					ComparePassword("hashedpassword", "validpassword").
					Return(true)

				mockUserRepo.EXPECT().
					FindRefreshToken(gomock.Any(), "user1").
					Return(entity.RefreshToken{Token: "existingToken"}, nil)

				mockUserRepo.EXPECT().
					DeleteRefreshToken(gomock.Any(), "existingToken").
					Return(nil)

				mockJWTManager.EXPECT().
					IssueAccessToken("user1").
					Return("validAccessToken", nil)

				mockJWTManager.EXPECT().
					IssueRefreshToken("user1").
					Return("validRefreshToken", nil)

				mockJWTManager.EXPECT().
					GetRefreshExpiresIn().
					Return(time.Hour * 24)

				mockUserRepo.EXPECT().
					SaveRefreshToken(gomock.Any(), "user1", "validRefreshToken", gomock.Any()).
					Return(assert.AnError)
			},
			expectedResponse: gen.PostLogin500JSONResponse{},
			expectedError:    assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := usecase.NewUseCase(
				mockUserRepo,
				mockCryptoPassword,
				mockJWTManager,
			)
			tt.setupMocks()
			resp, err := h.PostLogin(tt.args.ctx, tt.args.req)

			assert.Equal(t, tt.expectedResponse, resp)
			assert.Equal(t, tt.expectedError, err)
		})
	}
}
