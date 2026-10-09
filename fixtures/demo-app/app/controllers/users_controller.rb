class UsersController < ApplicationController
  def show
    @user = User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")
  end

  def redirect
    redirect_to params[:next]
  end
end
