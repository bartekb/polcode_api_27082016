Warsztaty Polcode, 27.08.2016 - API Tips & Tricks :-)
=========================================

System.
-------

Założenie, że OS to Ubutnu 14.04 LTS.

Pierwsze kroki.
---------------

```
1. Używamy RVM - http://railsapps.github.io/installing-rails.html
2. mkdir polcode_api
3. cd polcode_api/
4. rvm use ruby-2.3.0@polcode_api --ruby-version --create
5. gem install rails -v '4.2.7.1'
6. rails new . -m https://raw.github.com/RailsApps/rails-composer/master/composer.rb
7. rails g scaffold Category name:text parent_id:integer
8. rails g scaffold Product name:text price:decimal category:references
9. rake db:migrate
10. rails s
11. Testowo sprawdzamy http://localhost:3000/products w przeglądarce
```

Railsy posiadają API od samego początku. Poniżej kilka przykładów w jaki sposób możemy wejśc w interakcję z defaultowym
API Railsów w oparciu o aplikację przykładową i używającym JSON-a.

1. Pobieramy dane:

```
curl --request GET 'http://localhost:3000/products.json' => pusty wynik []
```

2. Próbujemy wysłać i zapisać dane:

```
curl --request POST 'http://localhost:3000/products.json' --data '[{"product":{"name":"test 1","price":"2.33"}}]'
```

niestety dostajemy błąd o braku zweryfikowanego CSRF: "Can't verify CSRF token authenticity".

3. Aby API działało musimy dodać w ApplicationController:

```ruby
skip_before_action :verify_authenticity_token
```

lub

```ruby
protect_from_forgery with: :null_session
```

a następnie restartujemy serwer. Czym różnią się te polecenia?

4. Ponownie wykonujemy zapytanie z pkt. 2

ale dostajemy błąd związany z ActionController::ParameterMissing. Czy wiemy dlaczego?

5. Poprawnie wykonany CURL będzie wyglądał tak:

```
  curl -X POST -H 'Content-Type: application/json' -d '{"product":{"name":"test 2","price":"4.33"}}' http://localhost:3000/products.json
```

Sprawdzamy znów zapytaniem z pkt. 1 czy dostaniemy wynik. Powinniśmy dostać produkt.

6. Gdybyśmy jednak chcieli stosować zabezpieczenie CSRF oto co musimy zrobić. W ApplicationController ponownie dodajemy:

```ruby
protect_from_forgery with: :exception
```

i restartujemy serwer.

7. Tym razem chcemy otrzymać token, dlatego wykonujemy:

```
  curl --cookie-jar cookie.txt localhost:3000 | grep 'csrf-token'
```
powinniśmy otrzymać coś w stylu:

```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  100 12173  100 12173    0     0  74296      <meta name="csrf-token" content="wnCpZsCGrbY7upnYVdnz7UZnbU39oxkflmSGio6u0U87iA7d/3b0UVwkngrhte0ijoGpFf9YFiJnKYs2nUZbSw==" />
  0 --:--:-- --:--:-- --:--:-- 74680
```

nasz klucz to: "wnCpZsCGrbY7upnYVdnz7UZnbU39oxkflmSGio6u0U87iA7d/3b0UVwkngrhte0ijoGpFf9YFiJnKYs2nUZbSw=="

8. Spróbujmy wykonać zapytanie bez CSRF:

```
  curl -v 'http://localhost:3000/products' -H "Accept: application/json" -H "Content-Type: application/json" -X POST -d '{"product":{"name":"test 2","price":"11.76"}}'
```

otrzymujemy ActionController::InvalidAuthenticityToken, natomiast dodając CSRF token do zapytania ORAZ przekazując prawidłowe ciasteczko do zapytania:

```
  curl -v 'http://localhost:3000/products' -H "Accept: application/json" -H "Content-Type: application/json" -H "X-CSRF-TOKEN: wnCpZsCGrbY7upnYVdnz7UZnbU39oxkflmSGio6u0U87iA7d/3b0UVwkngrhte0ijoGpFf9YFiJnKYs2nUZbSw==" -X POST -d '{"product":{"name":"test 2","price":"11.76"}}' --cookie cookie.txt
```

wróćmy jaknak dla wygody do wykonywania zapytań bez CSRF i cookie.

9. Dalsze zapytania typu CRUD mogą wyglądać tak:

9.1 view:

```
curl -v 'http://localhost:3000/products/1' -H "Accept: application/json" -H "Content-Type: application/json" -X GET
```

9.2 update:

```
  curl -v 'http://localhost:3000/products/1' -H "Accept: application/json" -H "Content-Type: application/json" -X PATCH -d '{"product":{"name":"test 2 updated","price":"666.66"}}'
```

9.3 delete

```
  curl -v 'http://localhost:3000/products/1' -H "Accept: application/json" -H "Content-Type: application/json" -X DELETE
```

Dodajemy znacznie bardziej zaawansowane API.

Czego nam brakuje? Co przydałoby się mieć w API aby było bardziej użyteczne dla nas.

1. bezpieczniejsze
2. wersjonowanie
3. testy
4. czytelniejsze

WERSJONOWANIE
-------------

W pierwszej kolejności dodajemy wersjonowanie aby zadbać o porządek w strukturze naszego API. Będzie to podstawa do dalszych
prac. Równocześnie dodajemy 'rails-api' będący od wersji 5.x Railsów domyślnym sposobem na tworzenie interfejsów API w RoR.
Główna jego zaleta to modularność i szeroka konfigurowalność.

1. Do pliku Gemfile dodajemy następujące gemy:

```ruby
  gem 'rails-api'
  gem 'versionist'
```

w trakcie będę wyjaśniał co do czego służy.

2. Gem 'rails-api'. Przeglądamy opcje w https://github.com/rails-api/rails-api

3. Gem 'versionist'. Przeglądamy opcje w: https://github.com/bploetz/versionist. Dodajemy w config/routes.rb:

```ruby
  api_version(module: "V1", :header => {:name => "Accept", :value => "application/polcode.com; version=1"}) do
    match '/version' => 'stats#version', via: :get
    resources :products
    resources :categories
  end
```

W przypadku gema versionist mamy do wyboru szereg różnych innych metod wersjonowania. Najbardziej powszechnym sposobem są opcje przekazywane w adresie URL (czy to za pomocą ścieżki czy parametru). Jednakże, najbardziej elastyczną formą jest uzycie nagłówków. Taką też wersje widzimy powyżej.

4. W katalogu z kontrolerami dodajemy następujące pliki, zwracając uwagę na właściwe ułożenie katalogów. Tworzymy
trzy kontrolery:

app/controllers/v1/base_controller.rb

```ruby
  class V1::BaseController < ActionController::API
  end
```

app/controllers/v1/products_controller.rb

```ruby
  class V1::ProductsController < V1::BaseController
    def index
      products = Product.all

      render(
        json: products.to_json
      )
    end
  end
```

app/controllers/v1/stats_controller.rb

```ruby
  class V1::StatsController < V1::BaseController
    def version
      render json: 'Polcode, Version 1, V20160827'
    end
  end
```

5. Teraz przeprowadzamy krótki test z linii komend, czy możemy dostać się do naszych kontrolerów:

```
  curl -v 'http://localhost:3000/version' -H " -H "Content-Type: application/json" -X GET
```

taka składnia nie zadziała, natomiast taka już tak:

```
  curl -v 'http://localhost:3000/version' -H "Accept: application/json; application/polcode.com; version=1" -H "Content-Type: application/json" -X GET
```

Analogicznie dla produktów:

```
  curl -v 'http://localhost:3000/products' -H "Accept: application/json; application/polcode.com; version=1" -H "Content-Type: application/json" -X GET
```

Poraz rozbudować nasze API i podnieść jego poziom bezpieczeństwa do akceptowalnej wartości.

AUTENTYKACJA
------------

1. Do pliku Gemfile dodajemy następujące gemy:

```ruby
  gem 'api-auth'
  gem 'rack-cors', :require => 'rack/cors'
```

wykonujemy po wszystkim:

```
  bundle
```

pamiętając o restarcie serwera jeśli nie wykonujemy 'bundle' z tego samego okna shella.

2. Tworzymy model odpowiedzialny za przechowywanie uprawnień dostępu do API, reprezentowany przez konto (Account)

```
  rails g model Account name:string access_id:string authentication_token:string
```

po czym:

```
  rake db:migrate
```

3. W ciele klasy Account (app/models/account.rb) dodajemy generatory kluczy:

```ruby
  before_create :generate_access_identity
  before_create :generate_authentication_token

  private

  def generate_authentication_token
    loop do
      self.authentication_token = ApiAuth.generate_secret_key
      break unless Account.find_by(authentication_token: authentication_token)
    end
  end

  def generate_access_identity
    loop do
      self.access_id = SecureRandom.hex(6)
      break unless Account.find_by(access_id: access_id)
    end
  end
```

4. Następnie w konsoli Railsów (rails c) wykonujemy dodanie przykładowego konta:

```ruby
  Account.create name: 'Polcode user'
```

i sprawdzamy czy access_id oraz authentication_token są wypełnione:

```ruby
  Account.find_by(name: 'Polcode user').access_id
  Account.find_by(name: 'Polcode user').authentication_token
```

5. W ciele kontrolera ActionController::API (app/controllers/v1/base_controller.rb) dodajemy metodę,
która nie pozwoli na nieautoryzowany dostęp. W przypadku próby wykonania nieautoryzowanego zapytania
zwracamy błąd:

```ruby
  before_filter :api_authenticate

  protected

  def api_authenticate
    @current_account = Account.find_by_access_id(ApiAuth.access_id(request))
    if !@current_account.nil? && ApiAuth.authentic?(request, @current_account.authentication_token)
      return true
    else
      return unauthenticated!
    end
  end

  def unauthenticated!
    response.headers['WWW-Authenticate'] = "Token realm=Application"
    render json: { error: 'Bad credentials' }, status: 401
  end
```

6. Czas na szybki test:

```
  curl -v 'http://localhost:3000/version' -H "Accept: application/json; application/polcode.com; version=1" -H "Content-Type: application/json" -X GET
```

i otrzymujemy wynik w postaci JSON-a:

```
  {"error":"Bad credentials"}
```

Aby autentykacja zadziałała musimy przekazać odpowiedni parametr w nagłówkach. W tym celu napiszemy klienta w Ruby.

7. Wykorzystywanie klienta Ruby do wykonywania zapytań do API. W katalogu /spec tworzymy plik o nazwie rest_client.rb, a w jego treści umieszczamy poniższy kod:

```ruby
  require 'net/http'
  require 'api-auth'

  @access_id = 'xxx'
  @secret_key = 'xxx'

  headers = {
    'Accept' => "Accept: application/polcode.com; version=1",
    'Content-Type' =>'application/json'
  }

  base_uri = URI('http://localhost:3000/version')

  @request = Net::HTTP::Get.new(base_uri.path,
    'Accept' => "Accept: application/polcode.com; version=1"
  )

  @signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)

  puts "**** TEST RESPONSE\n\n"
  res = Net::HTTP.start(base_uri.hostname, base_uri.port) {|http|
    puts http.request(@signed_request).body
  }
  puts "\n**** END OF TEST RESPONSE"
```

zwracamy uwagę na to, że w zmiennych access_id oraz secret_key podajemy prawidłowe, wygenerowane wcześniej
zmienne.

Wykonanie skryptu odbywa się poprzez wywołanie w katalogu z projektem:

```
  ruby spec/rest_client.rb
```

8. W punkcie 1-szym dodaliśmy gem rack-cors. Jego głównym zadaniem jest przytosowanie naszego API do tego
aby możliwe było wykonywanie zapytań spoza macieżystego serwera. Mówiąc krótko chcemmy uniknąć błędów związanych z Cross-Origin Resource Sharing. Aby gem zadziałał wymaga niewielkiej konfiguracji. W tym celu w pliku config/application.rb dodajemy:

```ruby
  config.middleware.insert_before 0, "Rack::Cors" do
    allow do
      origins '*'
      resource '*', :headers => :any, :methods => [:get, :post, :put, :patch, :delete, :options, :head]
    end
  end
```

ROZSZERZENIE KONTROLERÓW. STRONICOWANIE ORAZ DODANIE SERIALIZERÓW.
------------------------------------------------------------------

1. W pliku Gemfile dodajemy:

```ruby
  gem 'active_model_serializers'
  gem 'kaminari'
```

po czym wykonujemy bundle oraz restartujemy serwer.

2. W naszym kontrolerze V1::BaseController dodamy kod, którego zadaniem będzie poszerzenie dostepnej
funkcjonalności i wspieranie metodologii KISS oraz DRY. Dodajemy:

```ruby
  include ActionController::Serialization

  class V1::BaseController < ActionController::API
    before_filter :api_authenticate

    rescue_from ActiveRecord::RecordNotFound, with: :not_found!

    def api_error(status: 500, errors: [])
      unless Rails.env.production?
        puts errors.full_messages if errors.respond_to? :full_messages
      end
      head status: status and return if errors.empty?

      render json: jsonapi_format(errors).to_json, status: status
    end

    def invalid_resource!(errors = [])
      api_error(status: 422, errors: errors)
    end

    def not_found!
      return api_error(status: 404, errors: 'Not found')
    end

    def paginate(resource)
      resource = resource.page(params[:page] || 1)
      if params[:per_page]
        resource = resource.per_page(params[:per_page])
      end

      return resource
    end

    def meta_attributes(object)
      {
        current_page: object.current_page,
        next_page: object.next_page,
        prev_page: object.prev_page,
        total_pages: object.total_pages,
        total_count: object.count
      }
    end

    protected

      def api_authenticate
        @current_account = Account.find_by_access_id(ApiAuth.access_id(request))
        if !@current_account.nil? && ApiAuth.authentic?(request, @current_account.authentication_token)
          return true
        else
          return unauthenticated!
        end
      end

      def unauthenticated!
        response.headers['WWW-Authenticate'] = "Token realm=Application"
        render json: { error: 'Bad credentials' }, status: 401
      end

      def jsonapi_format(errors)
        return errors if errors.is_a? String
        errors_hash = {}
        errors.messages.each do |attribute, error|
          array_hash = []
          error.each do |e|
            array_hash << {attribute: attribute, message: e}
          end
          errors_hash.merge!({ attribute => array_hash })
        end

        return errors_hash
      end
  end
```

Poszczególne elementy pliku zostaną omówione na zajęciach.

3. Analogicznie postępujemy z kontrolerem produktów:

```ruby
  class V1::ProductsController < V1::BaseController
    def index
      products = paginate(Product.all)

      render(
        json: ActiveModel::ArraySerializer.new(
          products,
          each_serializer: Api::V1::ProductSerializer,
          root: 'products',
          meta: meta_attributes(products)
        )
      )
    end

    def show
      product = Product.find(params[:id])
      render json: Api::V1::ProductSerializer.new(product).to_json
    end

    def create
      product = Product.new(create_params)
      return api_error(status: 422, errors: product.errors) unless product.valid?

      product.save!

      render(
        json: Api::V1::ProductSerializer.new(product).to_json,
        status: 201,
        location: product_path(product),
        serializer: Api::V1::ProductSerializer
      )
    end

    def update
      product = Product.find(params[:id])

      if !product.update_attributes(update_params)
        return api_error(status: 422, errors: product.errors)
      end

      render(
        json: Api::V1::ProductSerializer.new(product).to_json,
        status: 200,
        location: product_path(product.id),
        serializer: Api::V1::ProductSerializer
      )
    end

    def destroy
      product = Product.find_by(id: params[:id])
      return api_error(status: 404) if product.blank?

      if !product.destroy
        return api_error(status: 500)
      end

      head status: 204
    end

    private

      def create_params
        params.require(:product).permit(:name, :category_id, :price)
      end

      def update_params
        create_params
      end
  end
```

4. W powyższym pliku pojawiły się serializery będące rozszerzeniem tego w jaki sposób Railsy operują na danych i renderują do uytkownika te elementy, które powinien on móc oglądać. W katalogu app/ tworzymy następujące katalogi:

```
  serializers/api/v1
```

a w nim dodajemy pliki:

4.1 BaseSerializer, czyli 'base_serializer.rb', z treścią:

```ruby
  class Api::V1::BaseSerializer < ActiveModel::Serializer
    def created_at
      object.created_at.in_time_zone.iso8601 if object.created_at
    end

    def updated_at
      object.updated_at.in_time_zone.iso8601 if object.created_at
    end
  end
```

4.2 ProductSerializer, czyli 'product_serializer.rb', a w nim:

```ruby
  class Api::V1::ProductSerializer < Api::V1::BaseSerializer
    attributes :id, :name, :category_name

    has_one :category

    def category_name
      object.category.try(:name)
    end
  end
```

TESTY RSPEC
-----------

1. Testy RSpec przeprowadzamy w katalogu spec/requests. W tym celu zakładamy w katalogu spec katalog requests:

```
  mkdir spec/requests
```

2. Tworzymy plik spec o nazwie stats_controller_spec.rb odnoszący się do naszego pierwszego kontrolera (czyli V1::StatsController), którego treść będzie następująca:

```ruby
  require 'rails_helper'

  RSpec.describe V1::StatsController do
    before(:each) do
      allow_any_instance_of(V1::StatsController).to receive(:api_authenticate).and_return(true)
    end

    it "should get version" do
      get '/version', {}, {'Accept' => 'application/polcode.com; version=1'}
      assert_response 200
      assert_match /Version 1/, response.body
    end
  end
```

3. W dalszej kolejności tworzymy plik spec odpowiedzialny za testy kontrolera produktów (products_controller_spec.rb), którego treść może wyglądać następująco:

```ruby
  require 'rails_helper'

  RSpec.describe V1::ProductsController do
    before(:each) do
      allow_any_instance_of(V1::ProductsController).to receive(:api_authenticate).and_return(true)
    end

    it "should list all products" do
      2.times{ create(:product) }
      get '/products', nil, {'Accept' => 'application/polcode.com; version=1'}
      assert_response 200
      expect(response_body["products"].size).to eq 2
    end

    it "should show details of the product" do
      product = create(:product)
      get product_url(product), nil, {'Accept' => 'application/polcode.com; version=1'}
      assert_response 200
    end

    it "should create new product" do
      mock_data = { product: {
          name: "Product Test",
          price: 1.22,
          category: create(:category)
        }
      }

      post '/products', mock_data, {'Accept' => 'application/polcode.com; version=1'}
      assert_response 201
      current_product = response_body["product"]
      expect(current_product["name"]).to eq "Product Test"
    end

    it "should update existing product" do
      product = create(:product)

      mock_data = { product: {
          name: "Updated Test Product"
        }
      }
      patch product_url(product), mock_data, {'Accept' => 'application/polcode.com; version=1'}
      assert_response 200
      current_product = response_body["product"]
      expect(current_product["name"]).to eq "Updated Test Product"
    end

    it 'should does nothing when the product does NOT exist' do
      product = create(:product)
      delete product_url(rand(100..1000)), nil, {'Accept' => 'application/polcode.com; version=1'}
      assert_response 404
    end


    it 'should delete the product' do
      product = create(:product)
      delete product_url(product), nil, {'Accept' => 'application/polcode.com; version=1'}
      assert_response 204
      expect(Product.find_by(id: product.id)).to eql(nil)
    end

    def response_body
      JSON.parse(response.body)
    end
  end
```

4. Testy wykonujemy następująco:

```
  rake db:test:prepare (tylko raz)
  rspec
```

PROSTY KLIENT API
-----------------

1. W pliku secret.yaml w katalogu config (sekcja development) dodajemy odpowiednie wpisy z kluczem dostępu oraz hasłem:


```ruby
  my_access_id: xxx
  my_authentication_token: xxx
  my_api_base_url: 'hhtp://localhost:3000'
  my_api_version: 1

```

2. W pliku application.rb dodajemy ścieżkę ładowania plików z lib:


```ruby
config.autoload_paths += ["#{config.root}/lib"]
```

3. Towrzymy plik my_polcode.rb w katalogu lib aplikacji, a jego treść wygląda nastepująco:

```ruby
  require 'net/http'
  require 'api-auth'

  class MyPolcode
    attr_accessor :access_id
    attr_accessor :authentication_token
    attr_accessor :base_url
    attr_accessor :headers
    attr_accessor :api_version

    def initialize(*args)
      @access_id = Rails.application.secrets.my_access_id
      @authentication_token = Rails.application.secrets.my_authentication_token
      @base_url = Rails.application.secrets.my_api_base_url
      @headers = {
        'Accept' => "Accept: application/polcode.com; version=#{Rails.application.secrets.my_api_version}",
        'Content-Type' =>'application/json'
      }
    end

    def version
      base_uri = URI("#{@base_url}/version")
      request = Net::HTTP::Get.new(base_uri.path, @headers)
      signed_request = ApiAuth.sign!(request, @access_id, @authentication_token)
      res = Net::HTTP.start(base_uri.hostname, base_uri.port) {|http|
        puts http.request(signed_request).body
      }
    end
  end
```

4. W jednej konsoli uruchamiamy serwer. W drugiej konsoli (rails c) testujemy naszego prostego klienta:

```ruby
  @plc = MyPolcode.new
  @plc.version
```

spodziewany wynik to:

```
  Polcode, Version 1, V20160827
```
