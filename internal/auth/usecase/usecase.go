package usecase

import (
	"auth_go_hw/internal/auth/entity"
	"auth_go_hw/internal/buildinfo"
	"auth_go_hw/internal/gateway/http/gen"
	"context"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UserRepository interface {
	RegisterUser(ctx context.Context, u entity.UserAccount) error
	FindUserByLogin(ctx context.Context, username string) (entity.UserAccount, error)
	//TODO replace to TokenRepo
	SaveRefreshToken(ctx context.Context, userID, token string, expiresAt time.Time) error
	DeleteRefreshToken(ctx context.Context, token string) error
	FindRefreshToken(ctx context.Context, userID string) (entity.RefreshToken, error)
}

type CryptoPassword interface {
	HashPassword(password string) ([]byte, error)
	ComparePassword(fromUser, fromDB string) bool
}

type JWTManager interface {
	IssueAccessToken(userID string) (string, error)
	IssueRefreshToken(userID string) (string, error)
	VerifyToken(tokenString string) (*jwt.Token, error)
	GetRefreshExpiresIn() time.Duration
}

type AuthUseCase struct {
	userRepo   UserRepository
	cryptoPsw  CryptoPassword
	jwtManager JWTManager
	buildInfo  buildinfo.BuildInfo
}

func NewUseCase(
	userRepo UserRepository,
	cryptoPsw CryptoPassword,
	jwtManager JWTManager,
	buildInfo buildinfo.BuildInfo,
) AuthUseCase {
	return AuthUseCase{
		userRepo:   userRepo,
		cryptoPsw:  cryptoPsw,
		jwtManager: jwtManager,
		buildInfo:  buildInfo,
	}
}

func (u AuthUseCase) PostLogin(ctx context.Context, request gen.PostLoginRequestObject) (gen.PostLoginResponseObject, error) {
	user, err := u.userRepo.FindUserByLogin(ctx, request.Body.Username)
	if err != nil {
		return gen.PostLogin500JSONResponse{}, nil
	}

	if !u.cryptoPsw.ComparePassword(user.Password, request.Body.Password) {
		return gen.PostLogin401JSONResponse{Error: "unauth"}, nil
	}

	// Check refresh token
	existingToken, err := u.userRepo.FindRefreshToken(ctx, user.UserID)
	if err != nil {
		return gen.PostLogin500JSONResponse{}, nil
	}

	// Delete refresh token
	if existingToken.Token != "" {
		err = u.userRepo.DeleteRefreshToken(ctx, existingToken.Token)
		if err != nil {
			return gen.PostLogin500JSONResponse{}, nil
		}
	}

	accessToken, err := u.jwtManager.IssueAccessToken(user.UserID)
	if err != nil {
		return gen.PostLogin500JSONResponse{}, err
	}

	refreshToken, err := u.jwtManager.IssueRefreshToken(user.UserID)
	if err != nil {
		return gen.PostLogin500JSONResponse{}, err
	}

	// Write refresh token to DB
	err = u.userRepo.SaveRefreshToken(ctx, user.UserID, refreshToken, time.Now().Add(u.jwtManager.GetRefreshExpiresIn()))
	if err != nil {
		return gen.PostLogin500JSONResponse{}, err
	}

	return gen.PostLogin200JSONResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (u AuthUseCase) PostRegister(ctx context.Context, request gen.PostRegisterRequestObject) (gen.PostRegisterResponseObject, error) {
	hashedPassword, err := u.cryptoPsw.HashPassword(request.Body.Password)
	if err != nil {
		return gen.PostRegister500JSONResponse{}, nil
	}

	user := entity.UserAccount{
		Username: request.Body.Username,
		Password: string(hashedPassword),
	}

	err = u.userRepo.RegisterUser(ctx, user)
	if err != nil {
		return gen.PostRegister500JSONResponse{}, nil
	}
	return gen.PostRegister201JSONResponse{
		Username: request.Body.Username,
	}, nil
}

func (u AuthUseCase) PostRefresh(ctx context.Context, request gen.PostRefreshRequestObject) (gen.PostRefreshResponseObject, error) {
	token, err := u.jwtManager.VerifyToken(request.Body.RefreshToken)
	if err != nil {
		log.Printf("Token verification failed: %v", err)
		return gen.PostRefresh401JSONResponse{}, nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid || claims["type"] != "refresh" {
		log.Printf("Invalid token claims or type: claims=%v", claims)
		return gen.PostRefresh401JSONResponse{}, nil
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		log.Printf("Invalid userID claim: %v", claims["sub"])
		return gen.PostRefresh401JSONResponse{}, nil
	}

	accessToken, err := u.jwtManager.IssueAccessToken(userID)
	if err != nil {
		return gen.PostRefresh500JSONResponse{}, err
	}

	return gen.PostRefresh200JSONResponse{
		AccessToken: accessToken,
	}, nil
}

func (u AuthUseCase) GetBuildinfo(ctx context.Context, request gen.GetBuildinfoRequestObject) (gen.GetBuildinfoResponseObject, error) {
	return gen.GetBuildinfo200JSONResponse{
		Arch:       u.buildInfo.Arch,
		BuildDate:  u.buildInfo.BuildDate,
		CommitHash: u.buildInfo.CommitHash,
		Compiler:   u.buildInfo.Compiler,
		GoVersion:  u.buildInfo.GoVersion,
		Os:         u.buildInfo.OS,
		Version:    u.buildInfo.Version,
	}, nil
}
